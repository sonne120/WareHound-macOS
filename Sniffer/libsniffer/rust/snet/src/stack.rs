//! Real smoltcp networking core.
//!
//! smoltcp is used for what it is: a userspace TCP/IP stack. In TUNNEL mode the
//! app's inbound IP packets are pushed here; smoltcp TERMINATES the TCP
//! connection (does the SYN/ACK handshake, reassembles the byte stream), and we
//! read the reassembled application bytes straight out of the smoltcp socket —
//! that is where L7 inspection (the ClientHello / SNI) now comes from, not a
//! hand-rolled packet parser.
//!
//! Data path:
//!   push_inbound(ip)  -> TunnelDevice.rx_queue (+ create a listening TCP socket
//!                        for a fresh destination on SYN)
//!   poll(now)         -> iface.poll() runs the TCP state machine; replies (SYN-ACK,
//!                        ACK, …) are emitted through TunnelDevice.tx -> Sink -> out_cb
//!                     -> for each connected socket we recv() the reassembled stream
//!                        and hand the first chunk to inspect.rs.

use std::collections::{HashMap, VecDeque};
use std::os::raw::c_void;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket,
};

use crate::inspect::Emitter;
use crate::SnetOutboundFn;

/// Wraps the C++ outbound callback so smoltcp's tx can reach the OS/tunnel.
pub struct Sink {
    pub out_cb: SnetOutboundFn,
    pub out_ctx: *mut c_void,
}
impl Sink {
    fn emit(&self, pkt: &[u8]) {
        (self.out_cb)(self.out_ctx, pkt.as_ptr(), pkt.len());
    }
}

/// A smoltcp `phy::Device` backed by the tunnel: rx is packets pushed from the
/// app, tx is packets smoltcp produced, handed back through the Sink.
pub struct TunnelDevice {
    rx_queue: VecDeque<Vec<u8>>,
    sink: Sink,
    mtu: usize,
}
impl TunnelDevice {
    fn new(sink: Sink) -> Self {
        Self { rx_queue: VecDeque::new(), sink, mtu: 1500 }
    }
    fn enqueue_rx(&mut self, pkt: &[u8]) {
        self.rx_queue.push_back(pkt.to_vec());
    }
}

pub struct RxTok {
    buf: Vec<u8>,
}
impl RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buf)
    }
}

pub struct TxTok<'a> {
    sink: &'a Sink,
}
impl<'a> TxToken for TxTok<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.sink.emit(&buf);
        r
    }
}

impl Device for TunnelDevice {
    type RxToken<'a> = RxTok where Self: 'a;
    type TxToken<'a> = TxTok<'a> where Self: 'a;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx_queue.pop_front()?;
        Some((RxTok { buf }, TxTok { sink: &self.sink }))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok { sink: &self.sink })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        // Compute checksums on the packets smoltcp sends (so a real client
        // accepts them); don't verify inbound checksums — the app's packets
        // arriving via the tunnel are already well-formed by the OS.
        c.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        c.checksum.tcp = smoltcp::phy::Checksum::Tx;
        c.checksum.udp = smoltcp::phy::Checksum::Tx;
        c
    }
}

/// Per-terminated-connection state.
struct Flow {
    handle: SocketHandle,
    dst: IpEndpoint,
    inspected: bool,
    /// Poll-clock time (ms) the flow was first observed, so we can report a
    /// best-effort time-to-first-byte as the connection RTT.
    created_ms: Option<u64>,
}

pub struct Stack {
    device: TunnelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    emitter: Option<Emitter>,
    flows: HashMap<(IpAddress, u16), Flow>,
}

impl Stack {
    pub fn new(sink: Sink, emitter: Option<Emitter>) -> Self {
        let mut device = TunnelDevice::new(sink);
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        // Terminate connections to ANY destination the app dials (tun2socks):
        // accept packets not addressed to our own IP, and give ourselves an
        // address/route so the TCP state machine can source replies.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 8));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1));

        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            emitter,
            flows: HashMap::new(),
        }
    }

    /// Feed one inbound IP packet from the app. On a fresh TCP SYN we create a
    /// smoltcp socket LISTENING on the original destination, so smoltcp will
    /// complete the handshake and terminate the connection.
    pub fn push_inbound(&mut self, ip_pkt: &[u8]) -> bool {
        if ip_pkt.is_empty() || !matches!(ip_pkt[0] >> 4, 4 | 6) {
            return false;
        }
        if let Some((dst, is_syn)) = parse_tcp_dst(ip_pkt) {
            if is_syn && !self.flows.contains_key(&(dst.addr, dst.port)) {
                let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
                let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
                let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                // Listen on the exact destination endpoint the app dialed.
                let listen = IpListenEndpoint { addr: Some(dst.addr), port: dst.port };
                if sock.listen(listen).is_ok() {
                    let handle = self.sockets.add(sock);
                    self.flows.insert(
                        (dst.addr, dst.port),
                        Flow { handle, dst, inspected: false, created_ms: None },
                    );
                }
            }
        }
        self.device.enqueue_rx(ip_pkt);
        true
    }

    /// Drive the TCP/IP stack once, then inspect any newly reassembled app data.
    pub fn poll(&mut self, now_ms: u64) {
        let ts = Instant::from_millis(now_ms as i64);
        self.iface.poll(ts, &mut self.device, &mut self.sockets);

        // Collect keys first to avoid holding a borrow of self.flows while we
        // mutably borrow self.sockets and self.emitter.
        let keys: Vec<(IpAddress, u16)> = self.flows.keys().copied().collect();
        for key in keys {
            let (handle, dst, already) = {
                let f = &self.flows[&key];
                (f.handle, f.dst, f.inspected)
            };
            // Stamp the first poll that observes the flow, so the RTT we report
            // below is the elapsed time until the first application bytes.
            if let Some(f) = self.flows.get_mut(&key) {
                if f.created_ms.is_none() {
                    f.created_ms = Some(now_ms);
                }
            }
            if already {
                continue;
            }
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            if !sock.can_recv() {
                continue;
            }
            let remote = sock.remote_endpoint();
            // Peek the first reassembled chunk (do NOT consume: keep it for a
            // real forwarder later; here we only need to read it once).
            let mut first: Vec<u8> = Vec::new();
            let _ = sock.recv(|data| {
                first.extend_from_slice(data);
                (data.len(), ())
            });
            if first.is_empty() {
                continue;
            }
            let bytes_recv = first.len() as u64;
            if let Some(em) = self.emitter.as_ref() {
                let src_ip = remote.map(|e| e.addr.to_string()).unwrap_or_default();
                let dst_ip = dst.addr.to_string();
                if dst.port == 443 {
                    crate::inspect::inspect_tls(em, &src_ip, &dst_ip, dst.port, &first);
                }
                // Report per-connection L4 health for this terminated flow.
                let rtt_ms = self.flows
                    .get(&key)
                    .and_then(|f| f.created_ms)
                    .map(|created| now_ms.saturating_sub(created) as u32)
                    .unwrap_or(0);
                crate::inspect::emit_tcp_metrics(
                    em, &src_ip, &dst_ip, dst.port, rtt_ms, 0, 0, bytes_recv,
                );
            }
            if let Some(f) = self.flows.get_mut(&key) {
                f.inspected = true;
            }
        }

        // Reclaim finished connections so `flows` and the smoltcp SocketSet do
        // NOT grow without bound — each flow pins ~70 KB of socket buffers, and
        // in a long-lived NetworkExtension every distinct destination would
        // otherwise leak forever. A flow is done once its socket reaches Closed,
        // or once it has been idle past the timeout and is no longer active.
        const IDLE_TIMEOUT_MS: u64 = 60_000;
        let stale: Vec<(IpAddress, u16)> = self
            .flows
            .iter()
            .filter(|(_, f)| {
                let sock = self.sockets.get::<tcp::Socket>(f.handle);
                // Fully closed: reap.
                let closed = matches!(sock.state(), tcp::State::Closed);
                // Peer closed its send half after we already read the flow's
                // data (e.g. CloseWait) — we won't get more, so reap it. Without
                // this, normally-closed connections would linger indefinitely
                // because we never initiate our own close.
                let peer_done = f.inspected && !sock.may_recv();
                // Backstop for connections that never handshaked / went silent.
                let idle = !sock.is_active()
                    && f
                        .created_ms
                        .map_or(false, |c| now_ms.saturating_sub(c) > IDLE_TIMEOUT_MS);
                closed || peer_done || idle
            })
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(f) = self.flows.remove(&key) {
                self.sockets.remove(f.handle);
            }
        }
    }
}

/// Parse an IPv4/IPv6 packet with smoltcp's wire types; return the TCP
/// destination endpoint and whether the SYN flag is set. None if not TCP.
fn parse_tcp_dst(ip: &[u8]) -> Option<(IpEndpoint, bool)> {
    match ip[0] >> 4 {
        4 => {
            let v4 = Ipv4Packet::new_checked(ip).ok()?;
            if v4.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(v4.payload()).ok()?;
            let dst = IpEndpoint::new(IpAddress::Ipv4(v4.dst_addr()), tcp.dst_port());
            Some((dst, tcp.syn()))
        }
        6 => {
            let v6 = Ipv6Packet::new_checked(ip).ok()?;
            if v6.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(v6.payload()).ok()?;
            let dst = IpEndpoint::new(IpAddress::Ipv6(v6.dst_addr()), tcp.dst_port());
            Some((dst, tcp.syn()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::raw::c_void;

    use crate::{SnetAnalyticsEvent, SnetEventType};
    use std::os::raw::c_char;

    thread_local! {
        static OUT: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
        static SNI: RefCell<Vec<String>> = RefCell::new(Vec::new());
        // (dst_ip, rtt_ms, bytes_recv) for each TcpMetrics event seen.
        static METRICS: RefCell<Vec<(String, u32, u64)>> = RefCell::new(Vec::new());
    }
    extern "C" fn out_cb(_ctx: *mut c_void, p: *const u8, l: usize) {
        let bytes = unsafe { std::slice::from_raw_parts(p, l) }.to_vec();
        OUT.with(|o| o.borrow_mut().push(bytes));
    }
    extern "C" fn sni_cb(_ctx: *mut c_void, ev: *const SnetAnalyticsEvent) {
        let ev = unsafe { &*ev };
        if matches!(ev.ty, SnetEventType::TlsClientHello) {
            let buf = unsafe { &ev.detail.tls.sni };
            let s: String = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            SNI.with(|v| v.borrow_mut().push(s));
        }
    }
    extern "C" fn metrics_cb(_ctx: *mut c_void, ev: *const SnetAnalyticsEvent) {
        let ev = unsafe { &*ev };
        if matches!(ev.ty, SnetEventType::TcpMetrics) {
            let dst: String =
                ev.dst_ip.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            let m = unsafe { ev.detail.tcp };
            METRICS.with(|v| v.borrow_mut().push((dst, m.rtt_ms, m.bytes_recv)));
        }
    }
    fn _silence(_: c_char) {}

    fn be16(v: &mut Vec<u8>, x: u16) { v.push((x >> 8) as u8); v.push(x as u8); }
    fn be32(v: &mut Vec<u8>, x: u32) { v.extend_from_slice(&x.to_be_bytes()); }

    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    // Build an IPv4+TCP packet (checksums left zero; rx verification is off).
    fn tcp_pkt(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        be16(&mut t, sp); be16(&mut t, dp); be32(&mut t, seq); be32(&mut t, ack);
        t.push(0x50); t.push(flags); be16(&mut t, 0xffff); be16(&mut t, 0); be16(&mut t, 0);
        t.extend_from_slice(payload);
        let total = 20 + t.len();
        let mut ip = vec![
            0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 6, 0, 0,
            10, 0, 0, 9,           // src 10.0.0.9 (the "client")
            93, 184, 216, 34,      // dst 93.184.216.34
        ];
        ip.extend_from_slice(&t);
        ip
    }

    // Pull the SYN-ACK smoltcp emitted and return its (seq, ack).
    fn find_synack() -> Option<(u32, u32)> {
        OUT.with(|o| {
            for p in o.borrow().iter() {
                if let Ok(v4) = Ipv4Packet::new_checked(&p[..]) {
                    if v4.next_header() == IpProtocol::Tcp {
                        if let Ok(t) = TcpPacket::new_checked(v4.payload()) {
                            if t.syn() && t.ack() {
                                return Some((t.seq_number().0 as u32, t.ack_number().0 as u32));
                            }
                        }
                    }
                }
            }
            None
        })
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut sni = vec![0x00, (h.len() >> 8) as u8, h.len() as u8];
        sni.extend_from_slice(h);
        let mut extd = vec![(sni.len() >> 8) as u8, sni.len() as u8];
        extd.extend_from_slice(&sni);
        let mut ext = vec![0x00, 0x00, (extd.len() >> 8) as u8, extd.len() as u8];
        ext.extend_from_slice(&extd);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&[(ext.len() >> 8) as u8, ext.len() as u8]);
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn smoltcp_really_terminates_tcp_and_reads_sni() {
        OUT.with(|o| o.borrow_mut().clear());
        SNI.with(|v| v.borrow_mut().clear());

        // Emitter records the SNI (proves L7 came THROUGH smoltcp's recv()).
        let sink = Sink { out_cb, out_ctx: std::ptr::null_mut() };
        let em = Emitter { an_cb: sni_cb, an_ctx: std::ptr::null_mut() };
        let mut st = Stack::new(sink, Some(em));

        // 1) client SYN -> smoltcp must answer SYN-ACK (real handshake).
        st.push_inbound(&tcp_pkt(40000, 443, 1000, 0, SYN, &[]));
        for t in 0..5 { st.poll(t * 5); }
        let (srv_seq, _srv_ack) = find_synack().expect("smoltcp must emit a real SYN-ACK");

        // 2) client ACK completes the handshake; ack = server_seq + 1.
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK, &[]));
        for t in 0..3 { st.poll(30 + t * 5); }

        // 3) client sends the TLS ClientHello as stream data -> smoltcp
        //    reassembles it; poll() recv()s it and inspects SNI.
        let ch = client_hello("smoltcp.example");
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK | PSH, &ch));
        for t in 0..5 { st.poll(60 + t * 5); }

        SNI.with(|v| {
            let sni = v.borrow();
            assert!(sni.iter().any(|s| s == "smoltcp.example"),
                    "SNI must be extracted from the smoltcp-reassembled stream, got {:?}", *sni);
        });
    }

    #[test]
    fn emits_tcp_metrics_for_terminated_flow() {
        OUT.with(|o| o.borrow_mut().clear());
        METRICS.with(|v| v.borrow_mut().clear());

        // Emitter records TcpMetrics events (proves L4 health flows to C++).
        let sink = Sink { out_cb, out_ctx: std::ptr::null_mut() };
        let em = Emitter { an_cb: metrics_cb, an_ctx: std::ptr::null_mut() };
        let mut st = Stack::new(sink, Some(em));

        // Full handshake, then a data segment so the flow yields bytes.
        st.push_inbound(&tcp_pkt(40000, 443, 1000, 0, SYN, &[]));
        for t in 0..5 { st.poll(t * 5); }
        let (srv_seq, _srv_ack) = find_synack().expect("smoltcp must emit a real SYN-ACK");
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK, &[]));
        for t in 0..3 { st.poll(30 + t * 5); }
        let ch = client_hello("metrics.example");
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK | PSH, &ch));
        for t in 0..5 { st.poll(60 + t * 5); }

        METRICS.with(|v| {
            let m = v.borrow();
            assert!(
                m.iter().any(|(dst, _rtt, bytes)| dst == "93.184.216.34" && *bytes > 0),
                "expected a TcpMetrics event with bytes_recv > 0, got {:?}",
                *m
            );
        });
    }

    #[test]
    fn reclaims_flow_after_peer_close() {
        OUT.with(|o| o.borrow_mut().clear());
        let sink = Sink { out_cb, out_ctx: std::ptr::null_mut() };
        let mut st = Stack::new(sink, None);

        // Handshake.
        st.push_inbound(&tcp_pkt(40000, 443, 1000, 0, SYN, &[]));
        for t in 0..5 { st.poll(t * 5); }
        let (srv_seq, _) = find_synack().expect("smoltcp must emit a real SYN-ACK");
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK, &[]));
        for t in 0..3 { st.poll(30 + t * 5); }

        // Client sends data (so the flow is inspected), then FINs.
        let ch = client_hello("bye.example");
        st.push_inbound(&tcp_pkt(40000, 443, 1001, srv_seq + 1, ACK | PSH, &ch));
        for t in 0..5 { st.poll(60 + t * 5); }
        assert_eq!(st.flows.len(), 1, "flow should still exist before peer close");

        let fin_seq = 1001 + ch.len() as u32;
        st.push_inbound(&tcp_pkt(40000, 443, fin_seq, srv_seq + 1, FIN | ACK, &[]));
        for t in 0..6 { st.poll(120 + t * 5); }

        assert!(
            st.flows.is_empty(),
            "flow must be reclaimed after peer close; {} still resident",
            st.flows.len()
        );
    }
}

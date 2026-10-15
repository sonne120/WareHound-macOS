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

pub struct Sink {
	pub out_cb: SnetOutboundFn,
	pub out_ctx: *mut c_void,
}
impl Sink {
	fn emit(&self, pkt: &[u8]) {
		(self.out_cb)(self.out_ctx, pkt.as_ptr(), pkt.len());
	}
}

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
		let result = f(&mut buf);
		self.sink.emit(&buf);
		result
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
		let mut caps = DeviceCapabilities::default();
		caps.medium = Medium::Ip;
		caps.max_transmission_unit = self.mtu;
		caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
		caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
		caps.checksum.udp = smoltcp::phy::Checksum::Tx;
		caps
	}
}

struct Flow {
	handle: SocketHandle,
	dst: IpEndpoint,
	inspected: bool,
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

	pub fn push_inbound(&mut self, ip_pkt: &[u8]) -> bool {
		if ip_pkt.is_empty() || !matches!(ip_pkt[0] >> 4, 4 | 6) {
			return false;
		}
		if let Some((dst, is_syn)) = parse_tcp_dst(ip_pkt) {
			if is_syn && !self.flows.contains_key(&(dst.addr, dst.port)) {
				let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
				let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
				let mut sock = tcp::Socket::new(rx_buf, tx_buf);
				let listen = IpListenEndpoint { addr: Some(dst.addr), port: dst.port };
				if sock.listen(listen).is_ok() {
					let handle = self.sockets.add(sock);
					self.flows.insert((dst.addr, dst.port), Flow { handle, dst, inspected: false });
				}
			}
		}
		self.device.enqueue_rx(ip_pkt);
		true
	}

	pub fn poll(&mut self, now_ms: u64) {
		let timestamp = Instant::from_millis(now_ms as i64);
		self.iface.poll(timestamp, &mut self.device, &mut self.sockets);

		let keys: Vec<(IpAddress, u16)> = self.flows.keys().copied().collect();
		for key in keys {
			let (handle, dst, inspected) = {
				let flow = &self.flows[&key];
				(flow.handle, flow.dst, flow.inspected)
			};
			if inspected {
				continue;
			}
			let sock = self.sockets.get_mut::<tcp::Socket>(handle);
			if !sock.can_recv() {
				continue;
			}
			let remote = sock.remote_endpoint();
			let mut first = Vec::new();
			let _ = sock.recv(|data| {
				first.extend_from_slice(data);
				(data.len(), ())
			});
			if first.is_empty() {
				continue;
			}
			if let Some(emitter) = self.emitter.as_ref() {
				let src_ip = remote.map(|e| e.addr.to_string()).unwrap_or_default();
				let dst_ip = dst.addr.to_string();
				if dst.port == 443 {
					crate::inspect::inspect_tls(emitter, &src_ip, &dst_ip, dst.port, &first);
				}
			}
			if let Some(flow) = self.flows.get_mut(&key) {
				flow.inspected = true;
			}
		}
	}
}

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

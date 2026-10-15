//! L7 inspection: the reason Rust is worth adding. We terminate the stream, so
//! the plaintext ClientHello and plaintext DNS are readable. Everything here is
//! passive and honest about its limits:
//!   - SNI, TLS version, and the count of CLIENT-offered ciphers: visible.
//!   - Server certificate / chosen cipher in TLS 1.3: NOT visible (encrypted).
//!   - SNI under ECH (Encrypted ClientHello): NOT visible.
//!   - Originating app / bundle id: NOT available from a tunnel packet.
//! Events are pushed to C++ via fixed inline buffers valid only for the call —
//! no ownership crosses FFI, so nothing leaks.

use std::os::raw::{c_char, c_void};

use crate::{
    fill_cstr, SnetAnalyticsEvent, SnetAnalyticsFn, SnetDetail, SnetDns, SnetEventType,
    SnetTcpMetrics, SnetTlsClientHello,
};

pub struct Emitter {
    pub an_cb: SnetAnalyticsFn,
    pub an_ctx: *mut c_void,
}

impl Emitter {
    fn send(&self, ev: &SnetAnalyticsEvent) {
        (self.an_cb)(self.an_ctx, ev as *const _);
    }
}

fn blank_5tuple(src_ip: &str, dst_ip: &str, dst_port: u16) -> ([c_char; 64], [c_char; 64], u16) {
    let mut s = [0 as c_char; 64];
    let mut d = [0 as c_char; 64];
    fill_cstr(&mut s, src_ip);
    fill_cstr(&mut d, dst_ip);
    (s, d, dst_port)
}

/// TLS path: called by stack.rs for the first payload of a TCP flow to :443.
pub fn inspect_tls(em: &Emitter, src_ip: &str, dst_ip: &str, dst_port: u16, payload: &[u8]) {
    if let Some(ev) = parse_client_hello(src_ip, dst_ip, dst_port, payload) {
        em.send(&ev);
    }
}

/// DNS path: called by stack.rs for a UDP payload to :53. Emits the first
/// question as SNET_EVENT_DNS_QUERY (resolve_ms=0; answers matched later).
pub fn inspect_dns(em: &Emitter, src_ip: &str, dst_ip: &str, dst_port: u16, payload: &[u8]) {
    if let Some(ev) = parse_dns_query(src_ip, dst_ip, dst_port, payload) {
        em.send(&ev);
    }
}

/// TCP metrics path: called by stack.rs once a terminated flow yields data.
/// Best-effort and honest about smoltcp's limits:
///   - bytes_recv: real (bytes reassembled out of the smoltcp socket).
///   - rtt_ms: time-to-first-byte measured on the poll clock — a real latency,
///     the closest observable proxy since smoltcp exposes no RTT getter.
///   - retransmits / bytes_sent: not observable in terminate-only mode, so 0
///     (the snet.h contract explicitly allows leaving these zero).
pub fn emit_tcp_metrics(
    em: &Emitter,
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    rtt_ms: u32,
    retransmits: u32,
    bytes_sent: u64,
    bytes_recv: u64,
) {
    let (src, dst, port) = blank_5tuple(src_ip, dst_ip, dst_port);
    em.send(&SnetAnalyticsEvent {
        ty: SnetEventType::TcpMetrics,
        src_ip: src,
        dst_ip: dst,
        dst_port: port,
        detail: SnetDetail {
            tcp: SnetTcpMetrics { rtt_ms, retransmits, bytes_sent, bytes_recv },
        },
    });
}

/// Minimal, bounds-checked DNS question parser (no compression needed for a
/// query's own QNAME). Returns None on truncation or malformed input.
fn parse_dns_query(
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    payload: &[u8],
) -> Option<SnetAnalyticsEvent> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    // Walk labels starting after the 12-byte header.
    let mut pos = 12usize;
    let mut name = String::new();
    loop {
        let len = *payload.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer not expected in a query's QNAME
        }
        let end = pos.checked_add(len)?;
        let label = payload.get(pos..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        pos = end;
    }
    let qtype = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]);

    let (src, dst, port) = blank_5tuple(src_ip, dst_ip, dst_port);
    let mut qname = [0 as c_char; crate::SNET_STR_MAX];
    fill_cstr(&mut qname, &name);
    Some(SnetAnalyticsEvent {
        ty: SnetEventType::DnsQuery,
        src_ip: src,
        dst_ip: dst,
        dst_port: port,
        detail: SnetDetail {
            dns: SnetDns { qname, qtype, resolve_ms: 0 },
        },
    })
}

/// Best-effort SNI extraction from a TLS ClientHello.
fn parse_client_hello(
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    payload: &[u8],
) -> Option<SnetAnalyticsEvent> {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

    let (_, record) = parse_tls_plaintext(payload).ok()?;
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            let mut sni_buf = [0 as c_char; crate::SNET_STR_MAX];
            let mut offered = 0u16;

            // ciphers the CLIENT offered (server's actual choice is encrypted in 1.3)
            offered = ch.ciphers.len() as u16;

            if let Some(ext_bytes) = ch.ext {
                if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_bytes) {
                    for ext in exts {
                        if let TlsExtension::SNI(names) = ext {
                            if let Some((_, host)) = names.first() {
                                if let Ok(h) = std::str::from_utf8(host) {
                                    fill_cstr(&mut sni_buf, h);
                                }
                            }
                        }
                    }
                }
            }

            let (src, dst, port) = blank_5tuple(src_ip, dst_ip, dst_port);
            return Some(SnetAnalyticsEvent {
                ty: SnetEventType::TlsClientHello,
                src_ip: src,
                dst_ip: dst,
                dst_port: port,
                detail: SnetDetail {
                    tls: SnetTlsClientHello {
                        sni: sni_buf,
                        tls_version: u16::from(ch.version), // legacy record version
                        offered_cipher_count: offered,
                    },
                },
            });
        }
    }
    None
}

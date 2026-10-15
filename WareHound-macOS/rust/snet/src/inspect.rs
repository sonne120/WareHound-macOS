use std::os::raw::{c_char, c_void};

use crate::{
	fill_cstr, SnetAnalyticsEvent, SnetAnalyticsFn, SnetDetail, SnetDns, SnetEventType,
	SnetTlsClientHello,
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
	let mut src = [0 as c_char; 64];
	let mut dst = [0 as c_char; 64];
	fill_cstr(&mut src, src_ip);
	fill_cstr(&mut dst, dst_ip);
	(src, dst, dst_port)
}

pub fn inspect_tls(em: &Emitter, src_ip: &str, dst_ip: &str, dst_port: u16, payload: &[u8]) {
	if let Some(ev) = parse_client_hello(src_ip, dst_ip, dst_port, payload) {
		em.send(&ev);
	}
}

pub fn inspect_dns(em: &Emitter, src_ip: &str, dst_ip: &str, dst_port: u16, payload: &[u8]) {
	if let Some(ev) = parse_dns_query(src_ip, dst_ip, dst_port, payload) {
		em.send(&ev);
	}
}

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
	let mut pos = 12usize;
	let mut name = String::new();
	loop {
		let len = *payload.get(pos)? as usize;
		pos += 1;
		if len == 0 {
			break;
		}
		if len & 0xc0 != 0 {
			return None;
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

fn parse_client_hello(
	src_ip: &str,
	dst_ip: &str,
	dst_port: u16,
	payload: &[u8],
) -> Option<SnetAnalyticsEvent> {
	use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake};

	let (_, record) = parse_tls_plaintext(payload).ok()?;
	for msg in record.msg {
		if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
			let mut sni_buf = [0 as c_char; crate::SNET_STR_MAX];
			let offered = ch.ciphers.len() as u16;

			if let Some(ext_bytes) = ch.ext {
				if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_bytes) {
					for ext in exts {
						if let TlsExtension::SNI(names) = ext {
							if let Some((_, host)) = names.first() {
								if let Ok(host) = std::str::from_utf8(host) {
									fill_cstr(&mut sni_buf, host);
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
						tls_version: u16::from(ch.version),
						offered_cipher_count: offered,
					},
				},
			});
		}
	}
	None
}

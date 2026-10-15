//! Exports wrap bodies in catch_unwind: a panic must never unwind across the C boundary.

use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

mod stack;
mod inspect;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum SnetStatus {
    Ok = 0,
    ErrNull = 1,
    ErrPanic = 2,
    ErrBadPacket = 3,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum SnetEventType {
    TlsClientHello = 0,
    DnsQuery = 1,
    DnsAnswer = 2,
    TcpMetrics = 3,
}

pub const SNET_STR_MAX: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnetTlsClientHello {
    pub sni: [c_char; SNET_STR_MAX],
    pub tls_version: u16,
    pub offered_cipher_count: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnetDns {
    pub qname: [c_char; SNET_STR_MAX],
    pub qtype: u16,
    pub resolve_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnetTcpMetrics {
    pub rtt_ms: u32,
    pub retransmits: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[repr(C)]
pub union SnetDetail {
    pub tls: SnetTlsClientHello,
    pub dns: SnetDns,
    pub tcp: SnetTcpMetrics,
}

#[repr(C)]
pub struct SnetAnalyticsEvent {
    pub ty: SnetEventType,
    pub src_ip: [c_char; 64],
    pub dst_ip: [c_char; 64],
    pub dst_port: u16,
    pub detail: SnetDetail,
}

pub type SnetOutboundFn = extern "C" fn(out_ctx: *mut c_void, pkt: *const u8, len: usize);
pub type SnetAnalyticsFn = extern "C" fn(an_ctx: *mut c_void, ev: *const SnetAnalyticsEvent);

pub struct SnetContext {
    stack: stack::Stack,
}

unsafe impl Send for SnetContext {}

#[no_mangle]
pub extern "C" fn snet_create(
    out_cb: Option<SnetOutboundFn>,
    out_ctx: *mut c_void,
    an_cb: Option<SnetAnalyticsFn>,
    an_ctx: *mut c_void,
) -> *mut SnetContext {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let out_cb = match out_cb {
            Some(cb) => cb,
            None => return std::ptr::null_mut(),
        };
        let stack = stack::Stack::new(
            stack::Sink { out_cb, out_ctx },
            an_cb.map(|cb| inspect::Emitter { an_cb: cb, an_ctx }),
        );
        Box::into_raw(Box::new(SnetContext { stack }))
    }));
    result.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn snet_push_ip(ctx: *mut SnetContext, pkt: *const u8, len: usize) -> SnetStatus {
    if ctx.is_null() || pkt.is_null() || len == 0 {
        return SnetStatus::ErrNull;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let ctx = unsafe { &mut *ctx };
        let bytes = unsafe { std::slice::from_raw_parts(pkt, len) };
        ctx.stack.push_inbound(bytes)
    }));
    match result {
        Ok(true) => SnetStatus::Ok,
        Ok(false) => SnetStatus::ErrBadPacket,
        Err(_) => SnetStatus::ErrPanic,
    }
}

#[no_mangle]
pub extern "C" fn snet_poll(ctx: *mut SnetContext, now_ms: u64) -> SnetStatus {
    if ctx.is_null() {
        return SnetStatus::ErrNull;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let ctx = unsafe { &mut *ctx };
        ctx.stack.poll(now_ms);
    }));
    match result {
        Ok(()) => SnetStatus::Ok,
        Err(_) => SnetStatus::ErrPanic,
    }
}

#[no_mangle]
pub extern "C" fn snet_destroy(ctx: *mut SnetContext) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(ctx));
    }));
}

pub(crate) fn fill_cstr(dst: &mut [c_char], src: &str) {
    let n = dst.len();
    if n == 0 {
        return;
    }
    let bytes = src.as_bytes();
    let copy = bytes.len().min(n - 1);
    for i in 0..copy {
        dst[i] = bytes[i] as c_char;
    }
    dst[copy] = 0;
}

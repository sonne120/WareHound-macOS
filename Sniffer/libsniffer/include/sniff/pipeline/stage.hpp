// Whoever holds a PacketView owns its buffer until passed on or released.
#pragma once

#include "sniff/flow/flow_key.hpp"

#include <cstdint>

namespace sniff::pipeline {
enum class L4Protocol : uint8_t {
    Unknown = 0,
    Hopopt = 0,
    Icmp = 1,
    Igmp = 2,
    Ggp = 3,
    Ipv4 = 4,
    St = 5,
    Tcp = 6,
    Cbt = 7,
    Egp = 8,
    Igp = 9,
    Pup = 12,
    Emcon = 14,
    Chaos = 16,
    Udp = 17,
    Mux = 18,
    Hmp = 20,
    Prm = 21,
    Idp = 22,
    Trunk1 = 24,
    Trunk2 = 25,
    Leaf1 = 26,
    Rdp = 27,
    Irtp = 28,
    IsoTp4 = 29,
    Netblt = 30,
    MfeNsp = 31,
    MeritInp = 32,
    Dccp = 33,
    ThreePc = 34,
    Idpr = 35,
    Xtp = 36,
    Ddp = 37,
    IdprCmtp = 38,
    Tp = 39,
    Il = 40,
    Ipv6 = 41,
    Sdrp = 42,
    Routing = 43,
    Fragment = 44,
    Idrp = 45,
    Rsvp = 46,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Mobile = 55,
    Tlsp = 56,
    Skip = 57,
    Icmpv6 = 58,
    None = 59,
    Dstopts = 60,
    Nd = 77,
    Eigrp = 88,
    Ospf = 89,
    Ipip = 94,
    Encap = 97,
    Pim = 103,
    Ipcomp = 108,
    Vrrp = 112,
    Pgm = 113,
    L2tp = 115,
    Stp = 118,
    Smp = 121,
    Isis = 124,
    Sscopmce = 128,
    Sctp = 132,
    Fc = 133,
    Mh = 135,
    Udplite = 136,
    Mpls = 137,
    Manet = 138,
    Hip = 139,
    Shim6 = 140,
    Wesp = 141,
    Rohc = 142,
    Ethernet = 143,
    Unassigned = 233,
    Experimental = 253,
    Experimental2 = 254
};

struct PacketView {
    uint8_t*  data{nullptr}; // owned by BufferPool
    uint32_t  length{0};
    uint64_t  timestamp_ns{0};

    flow::FlowKey flow{};
    L4Protocol    l4{L4Protocol::Unknown};
    uint16_t      l4_offset{0};
    uint16_t      l3_offset{0};
    uint8_t       ip_ver{0};
    bool          parsed{false};
    uint8_t       tcp_flags{0};
    bool          checksum_ok{true};
};

static_assert(sizeof(PacketView) <= 64,
              "PacketView grew beyond a cache line — re-check fields");
}

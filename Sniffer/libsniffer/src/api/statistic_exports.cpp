#include "sniff/api/statistic_exports.h"
#include "sniff/sniff.hpp"
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

// Owning copy keeps the Pipeline alive even if fnStopCapture() detaches it concurrently.
extern std::shared_ptr<sniff::Pipeline> GetGlobalPipeline();

extern "C" {
SNIFFER_API void Sniffer_EnableNativeStats(void* sniffer, bool enable) {
    
}

SNIFFER_API bool Sniffer_IsNativeStatsEnabled(void* sniffer) {
    return true; 
}

SNIFFER_API bool Sniffer_GetCaptureStatistics(void* sniffer, NativeCaptureStatistics* stats) {
    if (!stats) return false;
    
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return false;

    auto s = p->stats();

    uint64_t total_bytes = 0;
    for (uint64_t b : s.reducer_bytes) total_bytes += b;

    uint32_t unique_protocols = 0;
    {
        uint64_t proto_totals[256] = {0};
        for (const auto& rc : s.proto_counts) {
            for (int i = 0; i < 256; ++i) proto_totals[i] += rc[i];
        }
        for (int i = 0; i < 256; ++i) if (proto_totals[i] > 0) ++unique_protocols;
    }

    // The same IP can appear in more than one reducer.
    std::unordered_set<uint32_t> src_ips, dst_ips;
    uint64_t active_flows = 0;
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            std::vector<sniff::pipeline::L4CounterReducer::StatEntryIP> tmp;
            l4->get_top_src_ips(tmp);
            for (const auto& e : tmp) src_ips.insert(e.ip);
            tmp.clear();
            l4->get_top_dst_ips(tmp);
            for (const auto& e : tmp) dst_ips.insert(e.ip);
            active_flows += l4->get_flow_count();
        }
    }

    stats->totalPackets    = s.captured;
    stats->totalBytes      = total_bytes;
    stats->activeFlows     = active_flows;
    stats->uniqueProtocols = unique_protocols;
    stats->uniqueSourceIPs = static_cast<uint32_t>(src_ips.size());
    stats->uniqueDestIPs   = static_cast<uint32_t>(dst_ips.size());
    stats->_reserved       = 0;
    stats->captureDrops    = s.capture_drops;
    stats->unparseable     = s.unparseable;
    stats->shuffleDrops    = s.shuffle_drops;

    return true;
}

SNIFFER_API int Sniffer_GetProtocolStats(void* sniffer, NativeProtocolStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;

    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return 0;

    auto s = p->stats();
    
   
    uint64_t proto_counts[256] = {0};
    for (const auto& reducer_counts : s.proto_counts) {
        for (int i = 0; i < 256; ++i) {
            proto_counts[i] += reducer_counts[i];
        }
    }

    int count = 0;
    for (int i = 0; i < 256 && count < maxCount; ++i) {
        if (proto_counts[i] > 0) {
            stats[count].protocol = static_cast<uint8_t>(i);
            stats[count].packetCount = proto_counts[i];
            stats[count].byteCount = 0; 
            count++;
        }
    }
    return count;
}

SNIFFER_API int Sniffer_GetTopSourceIPs(void* sniffer, NativeTalkerStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return 0;

    std::unordered_map<uint32_t, sniff::pipeline::L4CounterReducer::StatEntryIP> aggregated;
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            std::vector<sniff::pipeline::L4CounterReducer::StatEntryIP> local_stats;
            l4->get_top_src_ips(local_stats);
            for (const auto& s : local_stats) {
                aggregated[s.ip].ip = s.ip;
                aggregated[s.ip].count += s.count;
                aggregated[s.ip].bytes += s.bytes;
            }
        }
    }

    std::vector<sniff::pipeline::L4CounterReducer::StatEntryIP> sorted;
    for (const auto& kv : aggregated) sorted.push_back(kv.second);
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.count > b.count; });

    int count = 0;
    for (int i = 0; i < sorted.size() && count < maxCount; ++i) {
        stats[count].ipAddress = sorted[i].ip;
        stats[count].packetCount = sorted[i].count;
        stats[count].byteCount = sorted[i].bytes;
        count++;
    }
    return count;
}

SNIFFER_API int Sniffer_GetTopDestIPs(void* sniffer, NativeTalkerStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return 0;

    std::unordered_map<uint32_t, sniff::pipeline::L4CounterReducer::StatEntryIP> aggregated;
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            std::vector<sniff::pipeline::L4CounterReducer::StatEntryIP> local_stats;
            l4->get_top_dst_ips(local_stats);
            for (const auto& s : local_stats) {
                aggregated[s.ip].ip = s.ip;
                aggregated[s.ip].count += s.count;
                aggregated[s.ip].bytes += s.bytes;
            }
        }
    }

    std::vector<sniff::pipeline::L4CounterReducer::StatEntryIP> sorted;
    for (const auto& kv : aggregated) sorted.push_back(kv.second);
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.count > b.count; });

    int count = 0;
    for (int i = 0; i < sorted.size() && count < maxCount; ++i) {
        stats[count].ipAddress = sorted[i].ip;
        stats[count].packetCount = sorted[i].count;
        stats[count].byteCount = sorted[i].bytes;
        count++;
    }
    return count;
}

SNIFFER_API int Sniffer_GetTopPorts(void* sniffer, NativePortStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return 0;

    std::unordered_map<uint16_t, sniff::pipeline::L4CounterReducer::StatEntryPort> aggregated;
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            std::vector<sniff::pipeline::L4CounterReducer::StatEntryPort> local_stats;
            l4->get_top_ports(local_stats);
            for (const auto& s : local_stats) {
                aggregated[s.port].port = s.port;
                aggregated[s.port].count += s.count;
                aggregated[s.port].bytes += s.bytes;
            }
        }
    }

    std::vector<sniff::pipeline::L4CounterReducer::StatEntryPort> sorted;
    for (const auto& kv : aggregated) sorted.push_back(kv.second);
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.count > b.count; });

    int count = 0;
    for (int i = 0; i < sorted.size() && count < maxCount; ++i) {
        stats[count].port = sorted[i].port;
        stats[count].packetCount = sorted[i].count;
        stats[count].byteCount = sorted[i].bytes;
        count++;
    }
    return count;
}

SNIFFER_API void Sniffer_ClearStatistics(void* sniffer) {
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return;
    
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            l4->clear_stats();
        }
    }
}

SNIFFER_API uint64_t Sniffer_GetFlowCount(void* sniffer) {
    auto sp = GetGlobalPipeline();
    sniff::Pipeline* p = sniffer ? static_cast<sniff::Pipeline*>(sniffer) : sp.get();
    if (!p) return 0;

    uint64_t total_flows = 0;
    for (const auto& r : p->reducers()) {
        if (auto l4 = std::dynamic_pointer_cast<sniff::pipeline::L4CounterReducer>(r)) {
            total_flows += l4->get_flow_count();
        }
    }
    return total_flows;
}
} 

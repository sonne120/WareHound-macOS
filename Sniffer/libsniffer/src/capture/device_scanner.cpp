#include "sniff/capture/device_scanner.hpp"
#include <pcap.h>
#include <stdexcept>

namespace sniff::capture {
std::vector<std::string> DeviceScanner::ListDevices() {
    std::vector<std::string> deviceList;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
#else
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
#endif
        return deviceList;
    }

    int idx = 0;
    for (pcap_if_t* it = alldevs; it; it = it->next) {
        ++idx;
        std::string desc;
        if (it->description) {
            desc = std::to_string(idx) + "_" + it->description;
        } else {
            desc = std::to_string(idx) + "_" + it->name;
        }

        if (desc.size() > 53) desc.resize(53);
        size_t lastWhitespace = desc.find_last_of(" \t\n\r");
        if (lastWhitespace != std::string::npos) {
            desc.erase(lastWhitespace);
        }
        deviceList.push_back(desc);
    }

    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
    
    return deviceList;
}

std::string DeviceScanner::GetDeviceNameAt(int index) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
#ifdef _WIN32
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
#else
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
#endif
        return "en0";
    }

    std::string deviceName = "en0";
    pcap_if_t* dev = alldevs;
    for (int i = 0; dev != nullptr; ++i, dev = dev->next) {
        if (i == index) {
            deviceName = dev->name;
            break;
        }
    }
    
    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
    return deviceName;
}
}

#pragma once

#include "sniff/pipeline/stage.hpp"

#include <cstdint>
#include <unordered_map>

namespace sniff::analyzers {

class HandleProto {
public:
    // Destination port preferred (request direction), then source.
    static const char* app_name(uint8_t proto, uint16_t sport, uint16_t dport) {
        if (proto == 6) {
            if (const char* n = tcp_service(dport)) return n;
            if (const char* n = tcp_service(sport)) return n;
            return "TCP";
        }
        if (proto == 17) {
            if (const char* n = udp_service(dport)) return n;
            if (const char* n = udp_service(sport)) return n;
            return "UDP";
        }
        return get_name(static_cast<pipeline::L4Protocol>(proto));
    }

    // Excludes 443 on purpose so HTTPS keeps showing its TLS version.
    static const char* tls_app_name(uint16_t sport, uint16_t dport) {
        auto by_port = [](uint16_t p) -> const char* {
            switch (p) {
                case 636:  return "LDAPS";
                case 989:
                case 990:  return "FTPS";
                case 465:  return "SMTPS";
                case 995:  return "POP3S";
                case 993:  return "IMAPS";
                case 8883: return "MQTTS";
                case 5061: return "SIP-TLS";
                case 563:  return "NNTPS";
                case 6514: return "Syslog-TLS";
                case 5223: return "XMPP-TLS";
                case 5671: return "AMQPS";
                case 6697: return "IRC-TLS";
                case 8009: return "Chromecast";
                case 6443:
                case 10250: return "Kubernetes";
                case 5986: return "WinRM-TLS";
                case 3269: return "GC-LDAPS";
                case 9090: return "Prometheus";
                default:   return nullptr;
            }
        };
        if (const char* n = by_port(dport)) return n;
        return by_port(sport);
    }

    static const char* lookup(const std::unordered_map<uint16_t, const char*>& table,
                              uint16_t port) {
        auto it = table.find(port);
        return it == table.end() ? nullptr : it->second;
    }

    static const char* tcp_service(uint16_t port) {
        static const std::unordered_map<uint16_t, const char*> table = {
            {20,"FTP-DATA"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},
            {37,"TIME"},{43,"WHOIS"},{49,"TACACS"},{53,"DNS"},{70,"Gopher"},
            {79,"Finger"},{80,"HTTP"},{88,"Kerberos"},{102,"S7"},{109,"POP2"},
            {110,"POP3"},{111,"RPC"},{113,"Ident"},{119,"NNTP"},{135,"MSRPC"},
            {139,"NetBIOS-SSN"},{143,"IMAP"},{161,"SNMP"},{179,"BGP"},{194,"IRC"},
            {389,"LDAP"},{427,"SLP"},{443,"TLS"},{444,"SNPP"},{445,"SMB"},
            {465,"SMTPS"},{500,"ISAKMP"},{502,"Modbus"},{512,"EXEC"},{513,"RLOGIN"},
            {514,"Syslog"},{515,"LPD"},{520,"RIP"},{540,"UUCP"},{543,"KLOGIN"},
            {544,"KSHELL"},{548,"AFP"},{554,"RTSP"},{587,"Submission"},{591,"HTTP-Alt"},
            {631,"IPP"},{636,"LDAPS"},{646,"LDP"},{860,"iSCSI"},{873,"rsync"},
            {902,"VMware"},{989,"FTPS-DATA"},{990,"FTPS"},{993,"IMAPS"},{995,"POP3S"},
            {1025,"MS-RPC"},{1080,"SOCKS"},{1099,"Java-RMI"},{1194,"OpenVPN"},
            {1352,"Lotus-Notes"},{1433,"MSSQL"},{1434,"MSSQL"},{1521,"Oracle"},
            {1723,"PPTP"},{1883,"MQTT"},{2049,"NFS"},{2082,"cPanel"},{2083,"cPanel-SSL"},
            {2181,"ZooKeeper"},{2375,"Docker"},{2376,"Docker-TLS"},{2483,"Oracle"},
            {2484,"Oracle-SSL"},{3000,"HTTP-Alt"},{3128,"Squid"},{3268,"GC-LDAP"},
            {3306,"MySQL"},{3389,"RDP"},{3690,"SVN"},{4369,"EPMD"},{4443,"HTTPS-Alt"},
            {5000,"UPnP"},{5060,"SIP"},{5061,"SIP-TLS"},{5222,"XMPP"},{5269,"XMPP-Server"},
            {5432,"PostgreSQL"},{5555,"ADB"},{5601,"Kibana"},{5672,"AMQP"},{5900,"VNC"},
            {5938,"TeamViewer"},{5984,"CouchDB"},{6000,"X11"},{6379,"Redis"},
            {6443,"Kubernetes"},{6514,"Syslog-TLS"},{6667,"IRC"},{7000,"Cassandra"},
            {7001,"WebLogic"},{8000,"HTTP-Alt"},{8008,"HTTP-Alt"},{8080,"HTTP-Proxy"},
            {8081,"HTTP-Alt"},{8086,"InfluxDB"},{8088,"HTTP-Alt"},{8443,"HTTPS-Alt"},
            {8883,"MQTT-TLS"},{9000,"HTTP-Alt"},{9042,"Cassandra"},{9092,"Kafka"},
            {9093,"Kafka"},{29092,"Kafka"},
            {9100,"JetDirect"},{9200,"Elasticsearch"},{9300,"Elasticsearch"},{9418,"Git"},
            {11211,"Memcached"},{15672,"RabbitMQ"},{25565,"Minecraft"},{27017,"MongoDB"},
            {50000,"DB2"},
            {7,"Echo"},{9,"Discard"},{13,"Daytime"},{17,"QOTD"},{19,"Chargen"},
            {42,"WINS"},{69,"TFTP"},{115,"SFTP"},{152,"BFTP"},{153,"SGMP"},
            {170,"PrintSrv"},{175,"VMNET"},{199,"SMUX"},{209,"QMTP"},{210,"Z39.50"},
            {213,"IPX"},{259,"ESRO"},{264,"BGMP"},{311,"AppleShare"},{350,"MATIP"},
            {366,"ODMR"},{369,"Rpc2Portmap"},{371,"ClearCase"},{383,"HP-Alarm"},
            {384,"ARNS"},{387,"AURP"},{401,"UPS"},{434,"Mobile-IP"},{464,"KPasswd"},
            {468,"Photuris"},{487,"SAFT"},{488,"GSS-HTTP"},{497,"Retrospect"},
            {504,"Citadel"},{510,"FirstClass"},{517,"Talk"},{518,"NTalk"},{524,"NCP"},
            {525,"Timed"},{530,"Courier"},{532,"NetNews"},{533,"NetWall"},{556,"RemoteFS"},
            {560,"rmonitor"},{561,"monitor"},{563,"NNTPS"},{604,"TUNNEL"},{623,"IPMI"},
            {639,"MSDP"},{647,"DHCP-Fail"},{648,"RRP"},{651,"IEEE-MMS"},{654,"MMS"},
            {660,"MacOS-Srv"},{666,"Doom"},{674,"ACAP"},{690,"VATP"},{691,"MS-Exchange"},
            {698,"OLSR"},{700,"EPP"},{701,"LMP"},{706,"SILC"},{711,"CFDP-TDP"},
            {712,"TBRPF"},{720,"SMQP"},{749,"Kerb-Adm"},{750,"Kerberos-IV"},
            {782,"Conserver"},{783,"SpamD"},{808,"CCProxy"},{830,"NETCONF-SSH"},
            {843,"Flash-Policy"},{853,"DoT"},{861,"OWAMP"},{862,"TWAMP"},{888,"CDDBP"},
            {900,"IIOP"},{901,"SWAT"},{903,"VMware-Auth"},{912,"APEX"},{992,"Telnets"},
            {1058,"nim"},{1059,"nimreg"},{1214,"Kazaa"},{1241,"Nessus"},{1311,"Dell-OM"},
            {1337,"WASTE"},{1414,"IBM-MQ"},{1494,"Citrix-ICA"},{1512,"WINS-TCP"},
            {1524,"Ingres"},{1589,"VQP"},{1719,"H323-RAS"},{1720,"H.323"},{1755,"MMS-Media"},
            {1801,"MSMQ"},{1863,"MSNP"},{1935,"RTMP"},{1947,"SafeNet"},{2000,"Cisco-SCCP"},
            {2002,"Globe"},{2100,"AmiganetFS"},{2222,"EtherNet-IP"},{2302,"Halo"},
            {2323,"3D-Nfsd"},{2427,"MGCP"},{2500,"RTSSERV"},{2598,"Citrix-CGP"},
            {2967,"Symantec-AV"},{3020,"CIFS"},{3050,"Firebird"},{3074,"XboxLive"},
            {3260,"iSCSI-Tgt"},{3283,"AppleRemote"},{3299,"SAPRouter"},{3333,"Dec-Notes"},
            {3386,"GTP-Acct"},{3689,"DAAP"},{3702,"WS-Disc"},{3724,"WoW"},{3784,"BFD"},
            {3785,"BFD-Echo"},{3868,"Diameter"},{4000,"ICQ"},{4070,"Spotify"},
            {4321,"RWHOIS"},{4444,"Krb524"},{4567,"TRAM"},{4662,"eDonkey"},
            {4713,"PulseAudio"},{4730,"Gearman"},{4840,"OPC-UA"},{4843,"OPC-UA-TLS"},
            {4899,"Radmin"},{5001,"Iperf"},{5009,"AirportAdm"},{5050,"Yahoo-Msg"},
            {5190,"AIM"},{5223,"XMPP-Push"},{5228,"Google-GCM"},{5280,"XMPP-BOSH"},
            {5351,"NAT-PMP"},{5357,"WSDAPI"},{5500,"VNC-Rev"},{5631,"pcAnywhere"},
            {5666,"NRPE"},{5671,"AMQPS"},{5683,"CoAP"},{5684,"CoAP-DTLS"},{5722,"MS-DFSR"},
            {5800,"VNC-HTTP"},{5985,"WinRM"},{5986,"WinRM-SSL"},{6001,"X11-1"},
            {6112,"Battlenet"},{6129,"DameWare"},{6660,"IRC"},{6697,"IRC-TLS"},
            {6881,"BitTorrent"},{6969,"BT-Tracker"},{7070,"RealServer"},{7100,"X-FontSrv"},
            {7443,"OracleHTTPS"},{7474,"Neo4j"},{7547,"TR-069"},{7676,"IMQ"},
            {7777,"iChat-Srv"},{8005,"Tomcat-Adm"},{8009,"AJP"},{8069,"OdooERP"},
            {8087,"Riak"},{8089,"Splunk"},{8091,"Couchbase"},{8140,"Puppet"},
            {8222,"VMware-VI"},{8291,"MikroTik"},{8300,"Consul"},{8333,"Bitcoin"},
            {8500,"Consul-HTTP"},{8767,"TeamSpeak"},{8834,"Nessus-Web"},{8888,"HTTP-Alt"},
            {9001,"Tor-OR"},{9050,"Tor-SOCKS"},{9051,"Tor-Ctrl"},{9090,"Prometheus"},
            {9091,"Transmission"},{9443,"K8s-API"},{9600,"OMRON-FINS"},{9987,"TeamSpeak3"},
            {9999,"Abyss"},{10000,"Webmin"},{10250,"Kubelet"},{12345,"NetBus"},
            {13720,"Veritas"},{16993,"Intel-AMT"},{17500,"Dropbox"},{19132,"Bedrock"},
            {20000,"DNP3"},{27015,"Source"},{28017,"MongoDB-Web"},{32400,"Plex"},
            {44818,"EtherNet-IP"},{47001,"WinRM-HTTP"},
            {1344,"ICAP"},{2379,"etcd"},{2380,"etcd"},{5445,"SMB-Direct"},
            {7000,"AirPlay"},{34964,"PROFINET"},
        };
        return lookup(table, port);
    }

    static const char* udp_service(uint16_t port) {
        static const std::unordered_map<uint16_t, const char*> table = {
            {53,"DNS"},{67,"DHCP"},{68,"DHCP"},{69,"TFTP"},{88,"Kerberos"},
            {111,"RPC"},{123,"NTP"},{137,"NetBIOS-NS"},{138,"NetBIOS-DGM"},
            {161,"SNMP"},{162,"SNMP-Trap"},{177,"XDMCP"},{319,"PTP-Event"},
            {320,"PTP-General"},{389,"LDAP"},{443,"QUIC"},{500,"IKE"},{514,"Syslog"},
            {520,"RIP"},{521,"RIPng"},{623,"IPMI"},{1194,"OpenVPN"},{1434,"MSSQL-Mon"},
            {1645,"RADIUS"},{1646,"RADIUS"},{1701,"L2TP"},{1812,"RADIUS"},
            {1813,"RADIUS-Acct"},{1900,"SSDP"},{2049,"NFS"},{2152,"GTP-U"},
            {3478,"STUN"},{3479,"STUN"},{4500,"IPsec-NAT"},{4789,"VXLAN"},
            {5004,"RTP"},{5005,"RTCP"},{5060,"SIP"},{5353,"mDNS"},{5355,"LLMNR"},
            {6081,"Geneve"},{33434,"Traceroute"},{51820,"WireGuard"},
            {7,"Echo"},{9,"Discard"},{13,"Daytime"},{17,"QOTD"},{19,"Chargen"},
            {37,"TIME"},{42,"WINS"},{49,"TACACS"},{213,"IPX"},{318,"TSP"},
            {434,"Mobile-IP"},{464,"KPasswd"},{512,"biff"},{513,"who"},{517,"Talk"},
            {518,"NTalk"},{525,"Timed"},{546,"DHCPv6-C"},{547,"DHCPv6-S"},{560,"rmonitor"},
            {561,"monitor"},{626,"ASIA"},{749,"Kerb-Adm"},{750,"Kerberos-IV"},
            {853,"DoQ"},{1026,"Win-RPC"},{1701,"L2TP"},{1719,"H323-RAS"},{1812,"RADIUS"},
            {1985,"HSRP"},{2000,"Cisco-SCCP"},{2123,"GTP-C"},{2427,"MGCP"},{2483,"Oracle"},
            {3283,"AppleRemote"},{3389,"RDP-UDP"},{3671,"KNX"},{3702,"WS-Disc"},
            {3784,"BFD"},{5061,"SIP-TLS"},{5246,"CAPWAP-C"},{5247,"CAPWAP-D"},
            {5684,"CoAP-DTLS"},{6343,"sFlow"},{9993,"ZeroTier"},{11211,"Memcached"},
            {27015,"Source"},{47808,"BACnet"},
            {3074,"Xbox-Live"},{3544,"Teredo"},{3222,"GLBP"},{6081,"GENEVE"},
            {8801,"Zoom"},{8802,"Zoom"},{8803,"Zoom"},{27031,"Steam-Stream"},
            {27036,"Steam"},{41641,"Tailscale"},{50000,"Discord-Voice"},
            {34962,"PROFINET"},{34963,"PROFINET"},{34964,"PROFINET"},{5094,"HART-IP"},
        };
        return lookup(table, port);
    }

    static const char* get_name(pipeline::L4Protocol proto) {
        switch (proto) {
            case pipeline::L4Protocol::Unknown:      return "HOPOPT";
            case pipeline::L4Protocol::Icmp:         return "ICMP";
            case pipeline::L4Protocol::Igmp:         return "IGMP";
            case pipeline::L4Protocol::Ggp:          return "GGP";
            case pipeline::L4Protocol::Ipv4:         return "IPV4";
            case pipeline::L4Protocol::St:           return "ST";
            case pipeline::L4Protocol::Tcp:          return "TCP";
            case pipeline::L4Protocol::Cbt:          return "CBT";
            case pipeline::L4Protocol::Egp:          return "EGP";
            case pipeline::L4Protocol::Igp:          return "IGP";
            case pipeline::L4Protocol::Pup:          return "PUP";
            case pipeline::L4Protocol::Emcon:        return "EMCON";
            case pipeline::L4Protocol::Chaos:        return "CHAOS";
            case pipeline::L4Protocol::Udp:          return "UDP";
            case pipeline::L4Protocol::Mux:          return "MUX";
            case pipeline::L4Protocol::Hmp:          return "HMP";
            case pipeline::L4Protocol::Prm:          return "PRM";
            case pipeline::L4Protocol::Idp:          return "IDP";
            case pipeline::L4Protocol::Trunk1:       return "TRUNK1";
            case pipeline::L4Protocol::Trunk2:       return "TRUNK2";
            case pipeline::L4Protocol::Leaf1:        return "LEAF1";
            case pipeline::L4Protocol::Rdp:          return "RDP";
            case pipeline::L4Protocol::Irtp:         return "IRTP";
            case pipeline::L4Protocol::IsoTp4:       return "ISO-TP4";
            case pipeline::L4Protocol::Netblt:       return "NETBLT";
            case pipeline::L4Protocol::MfeNsp:       return "MFE-NSP";
            case pipeline::L4Protocol::MeritInp:     return "MERIT-INP";
            case pipeline::L4Protocol::Dccp:         return "DCCP";
            case pipeline::L4Protocol::ThreePc:      return "3PC";
            case pipeline::L4Protocol::Idpr:         return "IDPR";
            case pipeline::L4Protocol::Xtp:          return "XTP";
            case pipeline::L4Protocol::Ddp:          return "DDP";
            case pipeline::L4Protocol::IdprCmtp:     return "IDPR-CMTP";
            case pipeline::L4Protocol::Tp:           return "TP";
            case pipeline::L4Protocol::Il:           return "IL";
            case pipeline::L4Protocol::Ipv6:         return "IPV6";
            case pipeline::L4Protocol::Sdrp:         return "SDRP";
            case pipeline::L4Protocol::Routing:      return "ROUTING";
            case pipeline::L4Protocol::Fragment:     return "FRAGMENT";
            case pipeline::L4Protocol::Idrp:         return "IDRP";
            case pipeline::L4Protocol::Rsvp:         return "RSVP";
            case pipeline::L4Protocol::Gre:          return "GRE";
            case pipeline::L4Protocol::Esp:          return "ESP";
            case pipeline::L4Protocol::Ah:           return "AH";
            case pipeline::L4Protocol::Mobile:       return "MOBILE";
            case pipeline::L4Protocol::Tlsp:         return "TLSP";
            case pipeline::L4Protocol::Skip:         return "SKIP";
            case pipeline::L4Protocol::Icmpv6:       return "ICMPV6";
            case pipeline::L4Protocol::None:         return "NONE";
            case pipeline::L4Protocol::Dstopts:      return "DSTOPTS";
            case pipeline::L4Protocol::Nd:           return "ND";
            case pipeline::L4Protocol::Eigrp:        return "EIGRP";
            case pipeline::L4Protocol::Ospf:         return "OSPF";
            case pipeline::L4Protocol::Ipip:         return "IPIP";
            case pipeline::L4Protocol::Encap:        return "ENCAP";
            case pipeline::L4Protocol::Pim:          return "PIM";
            case pipeline::L4Protocol::Ipcomp:       return "IPCOMP";
            case pipeline::L4Protocol::Vrrp:         return "VRRP";
            case pipeline::L4Protocol::Pgm:          return "PGM";
            case pipeline::L4Protocol::L2tp:         return "L2TP";
            case pipeline::L4Protocol::Stp:          return "STP";
            case pipeline::L4Protocol::Smp:          return "SMP";
            case pipeline::L4Protocol::Isis:         return "ISIS";
            case pipeline::L4Protocol::Sscopmce:     return "SSCOPMCE";
            case pipeline::L4Protocol::Sctp:         return "SCTP";
            case pipeline::L4Protocol::Fc:           return "FC";
            case pipeline::L4Protocol::Mh:           return "MH";
            case pipeline::L4Protocol::Udplite:      return "UDPLITE";
            case pipeline::L4Protocol::Mpls:         return "MPLS";
            case pipeline::L4Protocol::Manet:        return "MANET";
            case pipeline::L4Protocol::Hip:          return "HIP";
            case pipeline::L4Protocol::Shim6:        return "SHIM6";
            case pipeline::L4Protocol::Wesp:         return "WESP";
            case pipeline::L4Protocol::Rohc:         return "ROHC";
            case pipeline::L4Protocol::Ethernet:     return "ETHERNET";
            case pipeline::L4Protocol::Unassigned:   return "UNASSIGNED";
            case pipeline::L4Protocol::Experimental: return "EXPERIMENTAL";
            case pipeline::L4Protocol::Experimental2:return "EXPERIMENTAL2";
            default:                                 return "OTHER";
        }
    }
};

} // namespace sniff::analyzers
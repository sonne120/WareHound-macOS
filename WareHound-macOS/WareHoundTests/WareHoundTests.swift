import Testing
@testable import WareHound

struct WareHoundTests {

    @Test func wellKnownServiceLabelsCoverCommonLinuxTraffic() {
        let expected: [(Int32, String)] = [
            (22, "SSH"),
            (88, "Kerberos"),
            (111, "RPCBind"),
            (445, "SMB"),
            (514, "RServices"),
            (631, "IPP"),
            (873, "Rsync"),
            (2049, "NFS"),
            (2375, "Docker"),
            (6443, "Kubernetes"),
            (10250, "Kubelet"),
            (11211, "Memcached"),
            (20000, "Webmin")
        ]

        for (port, label) in expected {
            #expect(PacketModel.serviceName(port: port) == label)
        }
    }

    @Test func wellKnownServiceLabelsCoverFamousApplicationProtocols() {
        let expected: [(Int32, String)] = [
            (1883, "MQTT"),
            (2181, "ZooKeeper"),
            (3000, "Grafana"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (5672, "RabbitMQ"),
            (6379, "Redis"),
            (8123, "ClickHouse"),
            (9090, "Prometheus"),
            (9092, "Kafka"),
            (9200, "Elasticsearch"),
            (27017, "MongoDB"),
            (50051, "gRPC")
        ]

        for (port, label) in expected {
            #expect(PacketModel.serviceName(port: port) == label)
        }
    }

}

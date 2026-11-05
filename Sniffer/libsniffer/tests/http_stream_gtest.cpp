#include <gtest/gtest.h>
#include <zlib.h>

#include <cstring>
#include <string>
#include <vector>

#include "sniff/api/http_exports.h"

namespace {

class HttpStreamTest : public ::testing::Test {
protected:
    void SetUp() override { SnifferHttp_Clear(); }
    void TearDown() override { SnifferHttp_Clear(); }

    static uint64_t open(const char* client, const char* server) {
        return SnifferHttp_OpenStream(client, server, SNIFFER_HTTP_SOURCE_PROXY);
    }
    static void feed(uint64_t stream, int direction, const std::string& bytes) {
        SnifferHttp_FeedStream(stream, direction, reinterpret_cast<const uint8_t*>(bytes.data()),
                               static_cast<int>(bytes.size()), 1'000'000);
    }
    static std::vector<SnifferHttpTransaction> rows() {
        std::vector<SnifferHttpTransaction> out(64);
        uint64_t latest = 0;
        out.resize(static_cast<size_t>(SnifferHttp_GetChanged(0, out.data(), static_cast<int>(out.size()), &latest)));
        return out;
    }
    static const SnifferHttpTransaction* find(const std::vector<SnifferHttpTransaction>& all, const char* target) {
        for (const auto& r : all) if (std::strcmp(r.target, target) == 0) return &r;
        return nullptr;
    }
    static std::string body(uint64_t id, int part) {
        const int n = SnifferHttp_GetBody(id, part, 1, nullptr, 0);
        std::string out(static_cast<size_t>(n > 0 ? n : 0), '\0');
        SnifferHttp_GetBody(id, part, 1, reinterpret_cast<uint8_t*>(out.data()), n);
        return out;
    }
    static std::string gzip(const std::string& in) {
        z_stream z{};
        deflateInit2(&z, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
        std::string out(1024, '\0');
        z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
        z.avail_in = static_cast<uInt>(in.size());
        z.next_out = reinterpret_cast<Bytef*>(out.data());
        z.avail_out = static_cast<uInt>(out.size());
        deflate(&z, Z_FINISH);
        out.resize(out.size() - z.avail_out);
        deflateEnd(&z);
        return out;
    }
};

TEST_F(HttpStreamTest, PairsKeepAliveExchangesAndDecodesBodies) {
    const uint64_t s = open("127.0.0.1:50000", "example.com:80");
    ASSERT_NE(s, 0u);
    feed(s, 0, "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const std::string json = "{\"hello\":\"world\"}";
    const std::string z = gzip(json);
    char size[16];
    std::snprintf(size, sizeof(size), "%zx", z.size());
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                                 "Transfer-Encoding: chunked\r\n\r\n" + std::string(size) + "\r\n" + z + "\r\n0\r\n\r\n";
    feed(s, 1, response.substr(0, 40));   // split mid-head
    feed(s, 1, response.substr(40));
    feed(s, 0, "POST /b HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc");
    feed(s, 1, "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno");
    SnifferHttp_CloseStream(s, nullptr);

    const auto all = rows();
    ASSERT_EQ(all.size(), 2u);
    const auto* a = find(all, "/a");
    const auto* b = find(all, "/b");
    ASSERT_TRUE(a && b);
    EXPECT_EQ(a->source, SNIFFER_HTTP_SOURCE_PROXY);
    EXPECT_STREQ(a->client, "127.0.0.1:50000");
    EXPECT_STREQ(a->server, "example.com:80");
    EXPECT_EQ(a->status, 200);
    EXPECT_TRUE(a->complete);
    EXPECT_EQ(body(a->id, 1), json);
    EXPECT_EQ(b->status, 404);
    EXPECT_EQ(body(b->id, 0), "abc");
    EXPECT_STREQ(b->error, "");
}

TEST_F(HttpStreamTest, ConnectTunnelCountsBytesUntilClosed) {
    const uint64_t s = open("127.0.0.1:50001", "secure.test:443");
    feed(s, 0, "CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n");
    feed(s, 1, "HTTP/1.1 200 Connection Established\r\n\r\n");
    feed(s, 0, std::string(500, '\x16'));
    feed(s, 1, std::string(3000, '\x17'));

    auto all = rows();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].status, 200);
    EXPECT_FALSE(all[0].complete);

    SnifferHttp_CloseStream(s, nullptr);
    all = rows();
    EXPECT_TRUE(all[0].complete);
    EXPECT_GT(all[0].requestBytes, 500);
    EXPECT_GT(all[0].responseBytes, 3000);
}

TEST_F(HttpStreamTest, CloseRecordsWhyExchangesEndedEarly) {
    const uint64_t cut = open("127.0.0.1:50002", "slow.test:80");
    feed(cut, 0, "GET /cut HTTP/1.1\r\nHost: slow.test\r\n\r\n");
    feed(cut, 1, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
    SnifferHttp_CloseStream(cut, "Proxy relay failed: reset");

    const uint64_t unanswered = open("127.0.0.1:50003", "gone.test:80");
    feed(unanswered, 0, "GET /unanswered HTTP/1.1\r\nHost: gone.test\r\n\r\n");
    SnifferHttp_CloseStream(unanswered, nullptr);

    const auto all = rows();
    const auto* c = find(all, "/cut");
    const auto* u = find(all, "/unanswered");
    ASSERT_TRUE(c && u);
    EXPECT_FALSE(c->complete);
    EXPECT_STREQ(c->error, "Proxy relay failed: reset");
    EXPECT_EQ(u->status, 0);
    EXPECT_STREQ(u->error, "Connection closed before a response");
}

TEST_F(HttpStreamTest, ClearSourceKeepsOtherSourcesAndSummaryIgnoresProxy) {
    const uint64_t s = open("127.0.0.1:50004", "example.com:80");
    feed(s, 0, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    SnifferHttpSummary summary;
    SnifferHttp_GetSummary(&summary);
    EXPECT_EQ(summary.total, 0u);

    SnifferHttp_ClearSource(SNIFFER_HTTP_SOURCE_CAPTURE);
    EXPECT_EQ(rows().size(), 1u);
    SnifferHttp_ClearSource(SNIFFER_HTTP_SOURCE_PROXY);
    EXPECT_TRUE(rows().empty());
    feed(s, 1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");   // stream was dropped with its rows
    EXPECT_TRUE(rows().empty());
}

}  // namespace

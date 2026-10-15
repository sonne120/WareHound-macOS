#include <gtest/gtest.h>
#include "sniff/sniff.hpp"

using namespace sniff;

TEST(PipelineTest, CanConstructWithDefaultConfig) {
    PipelineConfig cfg;
    cfg.interface_name = "test0";
    Pipeline pipeline(cfg);
    SUCCEED();
}

TEST(PipelineTest, StatsAreZeroOnInit) {
    PipelineConfig cfg;
    cfg.interface_name = "test0";
    Pipeline pipeline(cfg);
    PipelineStats stats = pipeline.stats();
    EXPECT_EQ(stats.captured, 0u);
    EXPECT_EQ(stats.capture_drops, 0u);
    EXPECT_EQ(stats.mapped, 0u);
    EXPECT_EQ(stats.unparseable, 0u);
    EXPECT_EQ(stats.shuffle_drops, 0u);
}

TEST(PipelineTest, ReducerCountMatchesConfig) {
    PipelineConfig cfg;
    cfg.interface_name = "test0";
    cfg.num_reducers = 3;
    Pipeline pipeline(cfg);
    EXPECT_EQ(pipeline.reducers().size(), 3u);
}

TEST(PipelineTest, MapperAndReducerCoresConfigurable) {
    PipelineConfig cfg;
    cfg.interface_name = "test0";
    cfg.mapper_cores = {1, 2};
    cfg.reducer_cores = {3, 4};
    Pipeline pipeline(cfg);
    SUCCEED();
}

TEST(PipelineTest, BufferPoolSizeConfigurable) {
    PipelineConfig cfg;
    cfg.interface_name = "test0";
    cfg.buffer_pool_size = 12345;
    Pipeline pipeline(cfg);
    SUCCEED();
}

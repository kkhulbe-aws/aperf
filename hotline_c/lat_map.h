/**
 * @file lat_map.h
 * @brief Latency map B-Tree for load/store latency aggregation.
 * @author Kaustubh Khulbe
 * @ingroup Graviton Software
 */

#ifndef LAT_MAP_H_
#define LAT_MAP_H_

#include <stdint.h>
#include <string.h>

#include "btree.h"
#include "log.h"
#include "perf_packets.h"
#include "sys.h"

#define UPDATE_HISTOGRAM(dst, src1, src2, level)                 \
  do {                                                           \
    dst.level.l1_bound_bin =                                     \
        src1->level.l1_bound_bin + src2->level.l1_bound_bin;     \
    dst.level.l2_bound_bin =                                     \
        src1->level.l2_bound_bin + src2->level.l2_bound_bin;     \
    dst.level.l3_bound_bin =                                     \
        src1->level.l3_bound_bin + src2->level.l3_bound_bin;     \
    dst.level.dram_bound_bin =                                   \
        src1->level.dram_bound_bin + src2->level.dram_bound_bin; \
  } while (0)

typedef struct completion_histogram {
  uint64_t l1_bound_bin;
  uint64_t l2_bound_bin;
  uint64_t l3_bound_bin;
  uint64_t dram_bound_bin;
} completion_histogram_t;

typedef struct lat_map_entry {
  char *filename;
  uint64_t offset;
  uint64_t total_latency;
  uint64_t issue_latency;
  uint64_t translation_latency;
  uint64_t saturated;
  uint64_t retired;
  completion_histogram_t l1, l2, l3, dram;
} lat_map_entry_t;

void init_lat_map();
void insert_lat_map_entry(lat_map_entry_t *entry);
void parse_lat_map_entry(aux_record_raw_t *record, lat_map_entry_t *entry,
                         char *filename, uint64_t offset);

extern struct btree *LAT_MAP;
#endif  // LAT_MAP_H_
#include "lat_map.h"

struct btree *LAT_MAP = NULL;

/// @brief B-Tree comparison function for `lat_map_entry_t`
/// @param a First entry to compare
/// @param b Second entry to compare
/// @param udata Unused
/// @return 1 if a > b, -1 if a < b, 0 if a = b
int lat_map_compare(const void *a, const void *b, void *udata) {
  const lat_map_entry_t *ua = a;
  const lat_map_entry_t *ub = b;
  if (ua->filename != NULL && ub->filename != NULL) {
    int cmp = strcmp(ua->filename, ub->filename);
    if (cmp != 0) return cmp;
  }

  if (ua->offset < ub->offset) return -1;
  if (ua->offset > ub->offset) return 1;

  return 0;
}

/// @brief Initializes the LAT_MAP
void init_lat_map() {
  LAT_MAP = btree_new(sizeof(lat_map_entry_t), 0, lat_map_compare, NULL);
  btree_clear(LAT_MAP);
}

/// @brief Inserts a `lat_map_entry_t` into the LAT_MAP
/// @param entry_to_insert Entry to insert
void insert_lat_map_entry(lat_map_entry_t *entry_to_insert) {
  lat_map_entry_t key = {.filename = entry_to_insert->filename,
                         .offset = entry_to_insert->offset};

  const lat_map_entry_t *entry = btree_get(LAT_MAP, &key);

  if (entry == NULL) {
    char *filename = strdup(entry_to_insert->filename);
    lat_map_entry_t new_entry = {0};
    new_entry.filename = filename;
    new_entry.offset = entry_to_insert->offset;
    btree_set(LAT_MAP, &new_entry);
  }

  entry = btree_get(LAT_MAP, &key);
  lat_map_entry_t updated_entry = {0};  // copy over existing + new stats into a
                                        // new entry, then call btree_set
  updated_entry.filename = entry->filename;
  updated_entry.offset = entry->offset;

  updated_entry.total_latency =
      entry->total_latency + entry_to_insert->total_latency;
  updated_entry.issue_latency =
      entry->issue_latency + entry_to_insert->issue_latency;
  updated_entry.translation_latency =
      entry->translation_latency + entry_to_insert->translation_latency;
  updated_entry.saturated = entry->saturated + entry_to_insert->saturated;
  updated_entry.retired = entry->retired + entry_to_insert->retired;

  UPDATE_HISTOGRAM(updated_entry, entry, entry_to_insert, l1);
  UPDATE_HISTOGRAM(updated_entry, entry, entry_to_insert, l2);
  UPDATE_HISTOGRAM(updated_entry, entry, entry_to_insert, l3);
  UPDATE_HISTOGRAM(updated_entry, entry, entry_to_insert, dram);

  btree_set(LAT_MAP, &updated_entry);
}

/// @brief Parses a raw SPE entry into a struct that LAT_MAP can use
/// @param record Raw record to parse
/// @param entry LAT_MAP struct to parse into
/// @param filename Filename to associate, decoded from `pc_to_file_offset`
/// @param offset File offset to associate, decoded from `pc_to_file_offset`
void parse_lat_map_entry(aux_record_raw_t *record, lat_map_entry_t *entry,
                         char *filename, uint64_t offset) {
  memset(entry, 0, sizeof(lat_map_entry_t));
  entry->saturated = (record->issue_lat == AUX_PACKET_SATURATED) ? 1 : 0;
  entry->retired = (record->events_packet & AUX_EVENT_RETIRED) ? 1 : 0;
  entry->filename = strdup(filename);
  entry->offset = offset;

  // don't update statistics if saturated
  if (entry->saturated) return;

  entry->total_latency = record->total_lat;
  entry->issue_latency = record->issue_lat;
  entry->translation_latency = record->x_lat;

  // determine which bin we need to update based on data source
  completion_histogram_t *bin;
  switch (record->data_source) {
    case DATA_SOURCE_L1:
      bin = &entry->l1;
      break;
    case DATA_SOURCE_L2:
      bin = &entry->l2;
      break;
    case DATA_SOURCE_LOCAL_CLUSTER:
    case DATA_SOURCE_PEER_CLUSTER:
    case DATA_SOURCE_SYSTEM_CACHE:
      bin = &entry->l3;
      break;
    default:
      bin = &entry->dram;
  }

  uint64_t execution_latency =
      entry->total_latency - entry->issue_latency - entry->translation_latency;

  if (execution_latency <= CPU_SYSTEM_CONFIG.latency_limits.l1_max_cycles)
    bin->l1_bound_bin = 1;
  else if (execution_latency <= CPU_SYSTEM_CONFIG.latency_limits.l2_max_cycles)
    bin->l2_bound_bin = 1;
  else if (execution_latency <= CPU_SYSTEM_CONFIG.latency_limits.l3_max_cycles)
    bin->l3_bound_bin = 1;
  else
    bin->dram_bound_bin = 1;
}
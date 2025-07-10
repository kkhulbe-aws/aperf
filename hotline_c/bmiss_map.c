#include "bmiss_map.h"

struct btree *BMISS_MAP = NULL;

/// @brief B-Tree function to compare the branch miss map entries
/// @param a First element to compare
/// @param b Second element to compare
/// @param udata Unused
/// @return 1 if a > b, -1 if a < b, 0 if equal
int bmiss_map_compare(const void *a, const void *b, void *udata) {
  const bmiss_map_entry_t *ua = a;
  const bmiss_map_entry_t *ub = b;
  if (ua->filename != NULL && ub->filename != NULL) {
    int cmp = strcmp(ua->filename, ub->filename);
    if (cmp != 0) return cmp;
  }

  if (ua->offset < ub->offset) return -1;
  if (ua->offset > ub->offset) return 1;

  return 0;
}

/// @brief Initializes the BMISS_MAP
void init_bmiss_map() {
  BMISS_MAP = btree_new(sizeof(bmiss_map_entry_t), 0, bmiss_map_compare, NULL);
  btree_clear(BMISS_MAP);
}

/// @brief Inserts a bmiss_map_entry_t into the BMISS_MAP
/// @param entry_to_insert Entry to insert
void insert_bmiss_map(bmiss_map_entry_t *entry_to_insert) {
  bmiss_map_entry_t key = {.filename = entry_to_insert->filename,
                           .offset = entry_to_insert->offset};

  const bmiss_map_entry_t *entry = btree_get(BMISS_MAP, &key);

  if (entry == NULL) {
    char *filename = strdup(entry_to_insert->filename);
    bmiss_map_entry_t new_entry = {0};
    new_entry.filename = filename;
    new_entry.offset = entry_to_insert->offset;
    btree_set(BMISS_MAP, &new_entry);
  }

  entry = btree_get(BMISS_MAP, &key);
  bmiss_map_entry_t updated_entry = {0};

  updated_entry.filename = entry->filename;
  updated_entry.offset = entry->offset;

  updated_entry.total_latency =
      entry->total_latency + entry_to_insert->total_latency;
  updated_entry.issue_latency =
      entry->issue_latency + entry_to_insert->issue_latency;
  updated_entry.saturated = entry->saturated + entry_to_insert->saturated;
  updated_entry.retired = entry->retired + entry_to_insert->retired;
  updated_entry.not_taken = entry->not_taken + entry_to_insert->not_taken;
  updated_entry.mispredicted =
      entry->mispredicted + entry_to_insert->mispredicted;
  updated_entry.branch_type = entry_to_insert->branch_type;

  btree_set(BMISS_MAP, &updated_entry);
}

/// @brief Parses the raw SPE record into the format the BMISS_MAP uses
/// @param record Raw SPE record
/// @param entry B-Tree entry to populate
/// @param filename filename to assign into the entry, decoded from
/// `pc_to_file_offset`
/// @param offset offset to assign into the entry, decoded from
/// `pc_to_file_offset`
void parse_bmiss_map_entry(aux_record_raw_t *record, bmiss_map_entry_t *entry,
                           char *filename, uint64_t offset) {
  memset(entry, 0, sizeof(bmiss_map_entry_t));
  entry->saturated = (record->issue_lat == AUX_PACKET_SATURATED) ? 1 : 0;
  entry->retired = (record->events_packet & AUX_EVENT_RETIRED) ? 1 : 0;
  entry->filename = strdup(filename);
  entry->offset = offset;

  // don't update statistics if saturated
  if (entry->saturated) return;

  entry->total_latency = record->total_lat;
  entry->issue_latency = record->issue_lat;
  entry->not_taken =
      (record->events_packet & AUX_EVENT_BRANCH_NOT_TAKEN) ? 1 : 0;
  entry->mispredicted = (record->events_packet & AUX_EVENT_BRANCH_MISS) ? 1 : 0;
  entry->branch_type = record->type;
}
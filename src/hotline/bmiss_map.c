#include "bmiss_map.h"

struct btree *bmiss_map = NULL;

/// @brief B-Tree function to compare the branch miss map entries
/// @param a First element to compare
/// @param b Second element to compare
/// @param udata Unused
/// @return 1 if a > b, -1 if a < b, 0 if equal
int bmiss_map_compare(const void *a, const void *b, void *udata) {
  const bmiss_map_entry_t *ua = a;
  const bmiss_map_entry_t *ub = b;
  if (ua->finode.ino > ub->finode.ino)
    return 1;
  else if (ua->finode.ino < ub->finode.ino)
    return -1;

  if (ua->finode.maj > ub->finode.maj)
    return 1;
  else if (ua->finode.maj < ub->finode.maj)
    return -1;

  if (ua->finode.min > ub->finode.min)
    return 1;
  else if (ua->finode.min < ub->finode.min)
    return -1;

  if (ua->finode.ino_generation > ub->finode.ino_generation)
    return 1;
  else if (ua->finode.ino_generation < ub->finode.ino_generation)
    return -1;

  if (ua->offset < ub->offset) return -1;
  if (ua->offset > ub->offset) return 1;

  return 0;
}

/// @brief Initializes the BMISS_MAP
void init_bmiss_map() {
  bmiss_map = btree_new(sizeof(bmiss_map_entry_t), 0, bmiss_map_compare, NULL);
  btree_clear(bmiss_map);
}

/// @brief Inserts a bmiss_map_entry_t into the BMISS_MAP
/// @param entry_to_insert Entry to insert
void insert_bmiss_map(bmiss_map_entry_t *entry_to_insert) {
  bmiss_map_entry_t key = {.finode = entry_to_insert->finode,
                           .offset = entry_to_insert->offset};

  const bmiss_map_entry_t *entry = btree_get(bmiss_map, &key);

  if (entry == NULL) {
    bmiss_map_entry_t new_entry = {0};
    new_entry.finode = entry_to_insert->finode;
    new_entry.offset = entry_to_insert->offset;
    btree_set(bmiss_map, &new_entry);
  }

  entry = btree_get(bmiss_map, &key);
  bmiss_map_entry_t updated_entry = {0};

  updated_entry.finode = entry->finode;
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

  btree_set(bmiss_map, &updated_entry);
}

/// @brief Parses the raw SPE record into the format the BMISS_MAP uses
/// @param record Raw SPE record
/// @param entry B-Tree entry to populate
/// @param filename filename to assign into the entry, decoded from
/// `pc_to_file_offset`
/// @param offset offset to assign into the entry, decoded from
/// `pc_to_file_offset`
void parse_bmiss_map_entry(aux_record_raw_t *record, bmiss_map_entry_t *entry,
                           finode_t *finode, uint64_t offset) {
  entry->saturated = (record->issue_lat == AUX_PACKET_SATURATED) ? 1 : 0;
  entry->retired = (record->events_packet & AUX_EVENT_RETIRED) ? 1 : 0;
  entry->finode.ino = finode->ino;
  entry->finode.maj = finode->maj;
  entry->finode.min = finode->min;
  entry->finode.ino_generation = finode->ino_generation;
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
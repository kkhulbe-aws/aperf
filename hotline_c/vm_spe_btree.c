#include "vm_spe_btree.h"

int vm_spe_btree_compare(const void *a, const void *b, void *data) {
  const struct vm_spe_btree_entry *a_entry =
      (const struct vm_spe_btree_entry *)a;
  const struct vm_spe_btree_entry *b_entry =
      (const struct vm_spe_btree_entry *)b;

  // bare minimum comparisons required to uniquely identify a VA to map SPE
  // records to
  if (a_entry->file_id < b_entry->file_id)
    return -1;
  else if (a_entry->file_id > b_entry->file_id)
    return 1;

  if (a_entry->offset < b_entry->offset)
    return -1;
  else if (a_entry->offset > b_entry->offset)
    return 1;

  if (a_entry->type < b_entry->type)
    return -1;
  else if (a_entry->type > b_entry->type)
    return 1;

  return 0;
}

bool vm_spe_btree_iter(const void *node, const void *data) {
  struct vm_spe_btree_entry *entry = (struct vm_spe_btree_entry *)node;

  return true;
}
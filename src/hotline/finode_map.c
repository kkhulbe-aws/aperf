#include "finode_map.h"

struct btree *finode_map = NULL;

int finode_compare(const void *a, const void *b, void *udata) {
    const finode_t *fa = &((const finode_map_entry_t *)a)->finode;
    const finode_t *fb = &((const finode_map_entry_t *)b)->finode;

    // Compare ino first as it's likely to be unique most often
    if (fa->ino != fb->ino)
        return (fa->ino > fb->ino) ? 1 : -1;
    
    // Then device numbers
    if (fa->maj != fb->maj)
        return (fa->maj > fb->maj) ? 1 : -1;
    
    if (fa->min != fb->min)
        return (fa->min > fb->min) ? 1 : -1;
    
    // Finally generation number
    if (fa->ino_generation != fb->ino_generation)
        return (fa->ino_generation > fb->ino_generation) ? 1 : -1;

    return 0;
}

void init_finode_map() {
  finode_map = btree_new(sizeof(finode_map_entry_t), 0, finode_compare, NULL);
  btree_clear(finode_map);
}

void insert_finode_entry(mmap2_record_t *record) {
    finode_map_entry_t entry;
    entry.finode.ino = record->ino;
    entry.finode.maj = record->maj;
    entry.finode.min = record->min;
    entry.finode.ino_generation = record->ino_generation;

    size_t fixed_size = offsetof(struct mmap2_record, filename);
    size_t filename_len =
        ((struct perf_event_header *) record)->size - fixed_size - sizeof(struct sample_id);

    entry.filename = strdup(record->filename);
    btree_set(finode_map, &entry);
}
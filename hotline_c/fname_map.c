#include "fname_map.h"

#include <stdio.h>

struct btree *FNAME_MAP = NULL;

/// @brief B-Tree compare function for FNAME_MAP structs
/// @param a First entry to compare
/// @param b Second entry to compare
/// @param udata Unused
/// @return 1 if a > b, -1 if a < b, 0 if a = b
int fname_compare(const void *a, const void *b, void *udata) {
  const filename_entry_t *ua = a;
  const filename_entry_t *ub = b;

  if (ua->pid < ub->pid) return -1;
  if (ua->pid > ub->pid) return 1;

  if (ua->filename != NULL && ub->filename != NULL) {
    int cmp = strcmp(ua->filename, ub->filename);
    if (cmp == 0) {
      // Compare ua->pid if filenames are equivalent
    }
    return cmp;
  }

  return 0;
}

/// @brief Perf does not emit MMAP2 records for already running processes.
/// We will read through /proc/.../maps and get the virtual address mappings.
void insert_initial_mappings() {
  DIR *proc_dir;
  struct dirent *pid_entry;

  proc_dir = opendir("/proc");
  ASSERT(proc_dir != NULL, "Unable to open /proc.");

  while ((pid_entry = readdir(proc_dir))) {
    if (!isdigit(pid_entry->d_name[0])) continue;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%.230s/maps",
             pid_entry->d_name);

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) continue;

    pid_t pid = atoi(pid_entry->d_name);
    char line[1024];

    while (fgets(line, sizeof(line), maps)) {
      unsigned long start, end;
      unsigned long offset;
      char perms[5];
      char path[256] = "";

      sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*u %255s", &start, &end, perms,
             &offset, path);

      if (path[0]) {
        // artificially create a record so we can reuse our insert_fname_map
        size_t filename_len = strlen(path);
        size_t total_size = sizeof(mmap2_record_t) + filename_len + 1;
        mmap2_record_t *record = (mmap2_record_t *)calloc(1, total_size);

        record->header.type = PERF_RECORD_MMAP2;
        record->header.size = total_size;
        record->pid = pid;
        record->addr = start;
        record->len = end - start;
        record->pgoff = offset;

        memcpy(record->filename, path, filename_len + 1);

        insert_fname_entry(record);
        free(record);
      }
    }
  }
}

/// @brief Initializes FNAME_MAP data structures
void init_fname_map() {
  FNAME_MAP = btree_new(sizeof(filename_entry_t), 0, fname_compare, NULL);
  btree_clear(FNAME_MAP);

  insert_initial_mappings();
}

/// @brief Inserts a new MMAP2 record into FNAME_MAP.
/// @param record Record to insert
void insert_fname_entry(mmap2_record_t *record) {
  filename_entry_t key = {.pid = record->pid, .filename = record->filename};

  const filename_entry_t *entry = btree_get(FNAME_MAP, &key);

  // If the key does not exist (NULL), set up a new key, and allocate a new
  // vector for the MMAP data
  if (entry == NULL) {
    char *filename = strdup(record->filename);

    filename_entry_t new_entry;
    new_entry.pid = record->pid;
    new_entry.filename = filename;

    new_entry.virtual_address_map = vector_create();

    btree_set(FNAME_MAP, &new_entry);
  }

  // After that, when it is guaranteed an entry exists, extract it
  // and insert the new offset mapping into the vector

  entry = btree_get(FNAME_MAP, &key);
  pid_virtual_map_entry_t **virtual_address_map = entry->virtual_address_map;

  pid_virtual_map_entry_t *virtual_entry =
      malloc(sizeof(pid_virtual_map_entry_t));
  virtual_entry->start = record->addr;
  virtual_entry->end = record->addr + record->len;
  virtual_entry->pgoff = record->pgoff;

  // Add the value directly to the vector
  vector_add(&entry->virtual_address_map, virtual_entry);
}

void free_filename_entry(filename_entry_t *entry_to_remove) {
  pid_virtual_map_entry_t **vmap = entry_to_remove->virtual_address_map;
  uint64_t vmap_size = vector_size(vmap);

  for (int j = 0; j < vmap_size; j++) {
    pid_virtual_map_entry_t *ventry = ((pid_virtual_map_entry_t **)vmap)[j];
    free(ventry);
  }

  vector_free(entry_to_remove->virtual_address_map);
  btree_delete(FNAME_MAP, entry_to_remove);
  free(entry_to_remove->filename);
  free(entry_to_remove);
}

/// @brief Removes all virtual offset mappings associated with a PID.
/// @param pid PID to remove mappings for
void remove_fname_entry(pid_t pid) {
  filename_entry_t **to_remove = vector_create();

  struct btree_iter *iter = btree_iter_new(FNAME_MAP);
  // @todo double check if .pid=pid should be there
  bool ok = btree_iter_seek(iter, &(filename_entry_t){.pid = pid});

  // First iterate through the b-tree, starting at the pivot .pid=pid.
  // Add all the file_name_entry_t structs into a vector. There can be
  // multiple as a binary can involve multiple files.
  while (ok) {
    filename_entry_t *entry = (filename_entry_t *)btree_iter_item(iter);

    if (entry->pid == pid) {
      filename_entry_t *copied = malloc(sizeof(filename_entry_t));
      memcpy(copied, entry, sizeof(filename_entry_t));
      vector_add(&to_remove, copied);
    }

    ok = btree_iter_next(iter);
  }

  // Then iterate through the vector we created in the previous step, and
  // free everything.
  uint64_t size = vector_size(to_remove);

  for (size_t i = 0; i < size; i++) {
    filename_entry_t *entry_to_remove = ((filename_entry_t **)to_remove)[i];
    free_filename_entry(entry_to_remove);
  }

  vector_free(to_remove);
}

/// @brief Converts an instruction pointer (program counter) into a filename and
/// file offset, given
///        the present active PID for the session.
/// @param pc PC to convert
/// @param pid Active PID
/// @param filename Passed in to populate filename
/// @param offset Passed in to populate file offset
/// @return -1 on failure to map, 0 on success
int pc_to_file_offset(uint64_t pc, pid_t pid, char **filename,
                      uint64_t *offset) {
  struct btree_iter *iter = btree_iter_new(FNAME_MAP);
  bool ok = btree_iter_seek(iter, &(filename_entry_t){});

  while (ok) {
    const filename_entry_t *entry = btree_iter_item(iter);
    if (entry == NULL || entry->pid != pid) {
      ok = btree_iter_next(iter);
      continue;
    };

    pid_virtual_map_entry_t **vmap = entry->virtual_address_map;
    uint64_t vmap_size = vector_size(vmap);

    for (size_t i = 0; i < vmap_size; i++) {
      pid_virtual_map_entry_t *ventry = ((pid_virtual_map_entry_t **)vmap)[i];

      if (pc >= ventry->start && pc < ventry->end) {
        *filename = strdup(entry->filename);
        ASSERT(filename != 0, "Failed to duplicate filename string.");
        *offset = pc - ventry->start + ventry->pgoff;

        return 0;
      }
    }

    ok = btree_iter_next(iter);
  }

  return -1;
}
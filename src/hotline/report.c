#include "report.h"

bmiss_map_entry_t *process_bmiss_map_entries(const char *filename,
                                             uint64_t *out_count) {
  FILE *fp = fopen(filename, "r");
  ASSERT(fp != NULL, "Failed to open binary file.");

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  int entry_count = 0;

  size_t capacity = 64;
  bmiss_map_entry_t *entries = malloc(capacity * sizeof(bmiss_map_entry_t));
  ASSERT(entries != NULL, "Failed to allocate memory for entries.");

  if ((read = getline(&line, &len, fp)) == -1) {
    printf("File %s\n", filename);
    free(line);
    free(entries);
    fclose(fp);
    return NULL;
  }

  while ((read = getline(&line, &len, fp)) != -1) {
    if (entry_count >= capacity) {
      capacity *= 2;
      bmiss_map_entry_t *temp =
          realloc(entries, capacity * sizeof(bmiss_map_entry_t));
      if (temp == NULL) {
        free(entries);
        free(line);
        fclose(fp);
        ASSERT(0, "Failed to reallocate memory for entries.");
        return NULL;
      }
      entries = temp;
    }

    bmiss_map_entry_t *entry = &entries[entry_count];

    // Temporary buffer for filename
    char temp_filename[1024];

    int result =
        sscanf(line, "%[^,],%lx,%lu,%lu,%lu,%lu,%lu,%lu,%hhu", temp_filename,
               &entry->offset, &entry->retired, &entry->not_taken,
               &entry->mispredicted, &entry->total_latency,
               &entry->issue_latency, &entry->saturated, &entry->branch_type);

      ASSERT(result == 9, "failed to sscanf line correctly.");
      // Allocate memory for the filename and copy it
      entry->filename = strdup(temp_filename);
      if (entry->filename == NULL) {
        // Handle memory allocation failure
        fprintf(stderr, "Failed to allocate memory for filename\n");
        continue;
      }
      entry_count++;
  }

  if (entry_count > 0) {
    bmiss_map_entry_t *temp =
        realloc(entries, entry_count * sizeof(bmiss_map_entry_t));
    if (temp != NULL) {
      entries = temp;
    }
  }

  *out_count = entry_count;
  free(line);
  fclose(fp);
  return entries;
}

lat_map_entry_t *process_lat_map_entries(const char *filename,
                                         uint64_t *out_count) {
  FILE *fp = fopen(filename, "r");
  ASSERT(fp != NULL, "Failed to open binary file.");

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  int entry_count = 0;

  size_t capacity = 64;
  lat_map_entry_t *entries = malloc(capacity * sizeof(lat_map_entry_t));
  ASSERT(entries != NULL, "Failed to allocate memory for entries.");

  if ((read = getline(&line, &len, fp)) == -1) {
    free(line);
    free(entries);
    fclose(fp);
    return NULL;
  }

  while ((read = getline(&line, &len, fp)) != -1) {
    if (entry_count >= capacity) {
      capacity *= 2;
      lat_map_entry_t *temp =
          realloc(entries, capacity * sizeof(lat_map_entry_t));
      if (temp == NULL) {
        free(entries);
        free(line);
        fclose(fp);
        ASSERT(0, "Failed to reallocate memory for entries.");
        return NULL;
      }
      entries = temp;
    }

    lat_map_entry_t *entry = &entries[entry_count];

    // Temporary buffer for filename
    char temp_filename[1024];

    int result = sscanf(line,
                        "%[^,],%lx,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,"
                        "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,"
                        "%ld",
                        temp_filename, &entry->offset, &entry->retired,
                        &entry->total_latency, &entry->issue_latency,
                        &entry->translation_latency, &entry->l1.l1_bound_bin,
                        &entry->l1.l2_bound_bin, &entry->l1.l3_bound_bin,
                        &entry->l1.dram_bound_bin, &entry->l2.l1_bound_bin,
                        &entry->l2.l2_bound_bin, &entry->l2.l3_bound_bin,
                        &entry->l2.dram_bound_bin, &entry->l3.l1_bound_bin,
                        &entry->l3.l2_bound_bin, &entry->l3.l3_bound_bin,
                        &entry->l3.dram_bound_bin, &entry->dram.l1_bound_bin,
                        &entry->dram.l2_bound_bin, &entry->dram.l3_bound_bin,
                        &entry->dram.dram_bound_bin, &entry->saturated);

    ASSERT(result == 23, "failed to sscanf line correctly.");
    // Allocate memory for the filename and copy it
    entry->filename = strdup(temp_filename);
    ASSERT(entry->filename != NULL, "Failed to copy filename.")
    entry_count++;
  }

  if (entry_count > 0) {
    lat_map_entry_t *temp =
        realloc(entries, entry_count * sizeof(lat_map_entry_t));
    if (temp != NULL) {
      entries = temp;
    }
  }

  *out_count = entry_count;
  free(line);
  fclose(fp);
  return entries;
}

FILE *setup_report_file(char *file_dir, char *filename) {
  size_t path_len = strlen(file_dir) + strlen(filename) + 2;
  char *filepath = malloc(path_len);
  ASSERT(filepath != NULL, "Failed to malloc file path.");
  snprintf(filepath, path_len, "%s/%s", file_dir, filename);
  FILE *fp = fopen(filepath, "w");
  ASSERT(fp != NULL, "Failed to open file for writing.");

  return fp;
}

int compare_bmiss_entries(const void *a, const void *b) {
  const bmiss_map_entry_t *entry_a = (const bmiss_map_entry_t *)a;
  const bmiss_map_entry_t *entry_b = (const bmiss_map_entry_t *)b;

  // Sort by total latency (descending)
  return entry_b->total_latency - entry_a->total_latency;
}

void generate_bmiss_report(char *file_dir, bmiss_map_entry_t *entries,
                           uint64_t count) {
  FILE *fp = setup_report_file(file_dir, "hotline_bmiss_map.csv");

  // write the header in
  fprintf(fp,
          "Type,Count,Avg_Total_Lat,Avg_Issue_Lat,Not_Taken,Mispredicted,"
          "Saturated,Location,Line,Function,Assembly\n");

  qsort(entries, count, sizeof(bmiss_map_entry_t), compare_bmiss_entries);
  for (size_t i = 0; i < count; i++) {
    const bmiss_map_entry_t *entry = &entries[i];

    debug_info_t *dinfo = get_debug_info(entry->filename, entry->offset);

    fprintf(fp, "%s,%ld,%.2f,%.2f,%ld,%ld,%ld,%s,%s,%s,%s\n",
            entries[i].branch_type == 0x01 ? "COND" : "IND", entries[i].retired,
            ((double)entries[i].total_latency / entries[i].retired),
            ((double)entries[i].issue_latency / entries[i].retired),
            entries[i].not_taken, entries[i].mispredicted, entries[i].saturated,
            dinfo->src_file, dinfo->line, dinfo->function, dinfo->assembly);
  }

  fclose(fp);
}

int compare_lat_exec_entries(const void *a, const void *b) {
  const lat_map_entry_t *entry_a = (const lat_map_entry_t *)a;
  const lat_map_entry_t *entry_b = (const lat_map_entry_t *)b;

  // Sort by execution latency (descending)
  return (entry_b->total_latency - entry_b->issue_latency -
          entry_b->translation_latency) -
         (entry_a->total_latency - entry_b->issue_latency -
          entry_b->translation_latency);
}

void print_exec_latency(FILE *fp, const lat_map_entry_t *entry,
                        const debug_info_t *dinfo) {
  fprintf(fp, "%.2f,%ld,%s,%s,%s,%s,%ld\n",
          (double)(entry->total_latency - entry->issue_latency -
                   entry->translation_latency) /
              entry->retired,
          entry->retired, dinfo->src_file, dinfo->line, dinfo->function,
          dinfo->assembly, entry->saturated);
}

int compare_lat_issue_entries(const void *a, const void *b) {
  const lat_map_entry_t *entry_a = (const lat_map_entry_t *)a;
  const lat_map_entry_t *entry_b = (const lat_map_entry_t *)b;

  // Sort by issue latency (descending)
  return entry_b->issue_latency - entry_a->issue_latency;
}

void print_issue_latency(FILE *fp, const lat_map_entry_t *entry,
                         const debug_info_t *dinfo) {
  fprintf(fp, "%.2f,%ld,%s,%s,%s,%s,%ld\n",
          (double)(entry->issue_latency) / entry->retired, entry->retired,
          dinfo->src_file, dinfo->line, dinfo->function, dinfo->assembly,
          entry->saturated);
}

int compare_translation_issue_entries(const void *a, const void *b) {
  const lat_map_entry_t *entry_a = (const lat_map_entry_t *)a;
  const lat_map_entry_t *entry_b = (const lat_map_entry_t *)b;

  // Sort by issue latency (descending)
  return entry_b->translation_latency - entry_a->translation_latency;
}

void print_translation_latency(FILE *fp, const lat_map_entry_t *entry,
                               const debug_info_t *dinfo) {
  fprintf(fp, "%.2f,%ld,%s,%s,%s,%s,%ld\n",
          (double)(entry->translation_latency) / entry->retired, entry->retired,
          dinfo->src_file, dinfo->line, dinfo->function, dinfo->assembly,
          entry->saturated);
}

int compare_completion_node_issue_entries(const void *a, const void *b) {
  const lat_map_entry_t *entry_a = (const lat_map_entry_t *)a;
  const lat_map_entry_t *entry_b = (const lat_map_entry_t *)b;

  // Sort by issue latency (descending)
  return entry_b->total_latency - entry_a->total_latency;
}

void print_completion_node(FILE *fp, const lat_map_entry_t *entry,
                           const debug_info_t *dinfo) {
  // Calculate totals for each level
  uint64_t l1_total = entry->l1.l1_bound_bin + entry->l1.l2_bound_bin +
                      entry->l1.l3_bound_bin + entry->l1.dram_bound_bin;
  uint64_t l2_total = entry->l2.l1_bound_bin + entry->l2.l2_bound_bin +
                      entry->l2.l3_bound_bin + entry->l2.dram_bound_bin;
  uint64_t l3_total = entry->l3.l1_bound_bin + entry->l3.l2_bound_bin +
                      entry->l3.l3_bound_bin + entry->l3.dram_bound_bin;
  uint64_t dram_total = entry->dram.l1_bound_bin + entry->dram.l2_bound_bin +
                        entry->dram.l3_bound_bin + entry->dram.dram_bound_bin;

  uint64_t grand_total = l1_total + l2_total + l3_total + dram_total;
  if (grand_total == 0) grand_total = 1;

  // Calculate level percentages
  double l1_pct = (double)l1_total / grand_total * 100.0;
  double l2_pct = (double)l2_total / grand_total * 100.0;
  double l3_pct = (double)l3_total / grand_total * 100.0;
  double dram_pct = (double)dram_total / grand_total * 100.0;

  // Calculate bin percentages for L1
  double l1_bins[4] = {
      l1_total > 0 ? (double)entry->l1.l1_bound_bin / l1_total * 100.0 : 0.0,
      l1_total > 0 ? (double)entry->l1.l2_bound_bin / l1_total * 100.0 : 0.0,
      l1_total > 0 ? (double)entry->l1.l3_bound_bin / l1_total * 100.0 : 0.0,
      l1_total > 0 ? (double)entry->l1.dram_bound_bin / l1_total * 100.0 : 0.0};

  // Calculate bin percentages for L2
  double l2_bins[4] = {
      l2_total > 0 ? (double)entry->l2.l1_bound_bin / l2_total * 100.0 : 0.0,
      l2_total > 0 ? (double)entry->l2.l2_bound_bin / l2_total * 100.0 : 0.0,
      l2_total > 0 ? (double)entry->l2.l3_bound_bin / l2_total * 100.0 : 0.0,
      l2_total > 0 ? (double)entry->l2.dram_bound_bin / l2_total * 100.0 : 0.0};

  // Calculate bin percentages for L3
  double l3_bins[4] = {
      l3_total > 0 ? (double)entry->l3.l1_bound_bin / l3_total * 100.0 : 0.0,
      l3_total > 0 ? (double)entry->l3.l2_bound_bin / l3_total * 100.0 : 0.0,
      l3_total > 0 ? (double)entry->l3.l3_bound_bin / l3_total * 100.0 : 0.0,
      l3_total > 0 ? (double)entry->l3.dram_bound_bin / l3_total * 100.0 : 0.0};

  // Calculate bin percentages for DRAM
  double dram_bins[4] = {
      dram_total > 0 ? (double)entry->dram.l1_bound_bin / dram_total * 100.0
                     : 0.0,
      dram_total > 0 ? (double)entry->dram.l2_bound_bin / dram_total * 100.0
                     : 0.0,
      dram_total > 0 ? (double)entry->dram.l3_bound_bin / dram_total * 100.0
                     : 0.0,
      dram_total > 0 ? (double)entry->dram.dram_bound_bin / dram_total * 100.0
                     : 0.0};

  fprintf(fp,
          "%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | %.2f,"
          "%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | "
          "%.2f,%s,%s,%s,%s\n",
          l1_pct, l1_bins[0], l1_bins[1], l1_bins[2], l1_bins[3], l2_pct,
          l2_bins[0], l2_bins[1], l2_bins[2], l2_bins[3], l3_pct, l3_bins[0],
          l3_bins[1], l3_bins[2], l3_bins[3], dram_pct, dram_bins[0],
          dram_bins[1], dram_bins[2], dram_bins[3], dinfo->src_file,
          dinfo->line, dinfo->function, dinfo->assembly);
}

void write_lat_map_sub_report(lat_map_entry_t *entries, uint64_t count,
                              FILE *fp,
                              int (*compare_fn)(const void *, const void *),
                              void (*print_fn)(FILE *, const lat_map_entry_t *,
                                               const debug_info_t *)) {
  qsort(entries, count, sizeof(lat_map_entry_t), compare_fn);

  for (size_t i = 0; i < count; i++) {
    const lat_map_entry_t *entry = &entries[i];
    debug_info_t *dinfo = get_debug_info(entry->filename, entry->offset);
    print_fn(fp, entry, dinfo);
  }
}

void generate_lat_report(char *file_dir, lat_map_entry_t *entries,
                         uint64_t count) {
  FILE *exec_fp =
      setup_report_file(file_dir, "hotline_lat_map_exec_report.csv");
  FILE *issue_fp =
      setup_report_file(file_dir, "hotline_lat_map_issue_report.csv");
  FILE *translation_fp =
      setup_report_file(file_dir, "hotline_lat_map_translation_report.csv");
  FILE *completion_fp =
      setup_report_file(file_dir, "hotline_lat_map_completion_report.csv");

  // write the headers in
  fputs("Avg. Exec Latency,Count,Location,Line,Function,Assembly,Saturated\n",
        exec_fp);

  fputs("Avg. Issue Latency,Count,Location,Line,Function,Assembly,Saturated\n",
        issue_fp);

  fputs(
      "Avg. Translation "
      "Latency,Count,Location,Line,Function,Assembly,Saturated\n",
      translation_fp);

  fputs(
      "L1 (%),L1 bins (% | % | % | %),L2 (%),L2 bins (% | % | % | %),"
      "L3 (%),L3 bins (% | % | % | %),DRAM (%),DRAM bins (% | % | % | %),"
      "Location,Line,Function,Assembly\n",
      completion_fp);

  write_lat_map_sub_report(entries, count, exec_fp, compare_lat_exec_entries,
                           print_exec_latency);
  write_lat_map_sub_report(entries, count, issue_fp, compare_lat_issue_entries,
                           print_issue_latency);
  write_lat_map_sub_report(entries, count, translation_fp,
                           compare_translation_issue_entries,
                           print_translation_latency);
  write_lat_map_sub_report(entries, count, completion_fp,
                           compare_completion_node_issue_entries,
                           print_completion_node);
}

int deserialize_maps(int argc, char *argv[]) {
  init_fname_binary_btree();
  parse_arguments(argc, argv);

  uint64_t count;

  // For bmiss map data
  size_t bmiss_len = strlen(PROFILE_CONFIGURATION.data_dir) +
                     strlen(PROFILE_CONFIGURATION.bmiss_map_filename) + 1;
  char *bmiss_data_path = malloc(bmiss_len);
  if (!bmiss_data_path) {
    perror("Failed to allocate memory for bmiss path");
    return -1;
  }
  int res = snprintf(bmiss_data_path, bmiss_len, "%s/%s",
                     PROFILE_CONFIGURATION.data_dir,
                     PROFILE_CONFIGURATION.bmiss_map_filename);
  ASSERT(res > 0, "snprintf failed.");

  // Process bmiss entries
  bmiss_map_entry_t *b_entries =
      process_bmiss_map_entries(bmiss_data_path, &count);
  generate_bmiss_report(PROFILE_CONFIGURATION.report_dir, b_entries, count);
  free(bmiss_data_path);

  // For lat map data
  size_t lat_len = strlen(PROFILE_CONFIGURATION.data_dir) +
                   strlen(PROFILE_CONFIGURATION.lat_map_filename) + 1;
  char *lat_data_path = malloc(lat_len);
  if (!lat_data_path) {
    perror("Failed to allocate memory for lat path");
    return -1;
  }
  res =
      snprintf(lat_data_path, lat_len, "%s/%s", PROFILE_CONFIGURATION.data_dir,
               PROFILE_CONFIGURATION.lat_map_filename);
  ASSERT(res > 0, "snprintf failed.");

  // Process lat entries
  lat_map_entry_t *l_entries = process_lat_map_entries(lat_data_path, &count);
  generate_lat_report(PROFILE_CONFIGURATION.report_dir, l_entries, count);
  free(lat_data_path);

  return 0;
}

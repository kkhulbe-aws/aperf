#include "report.h"

static const Dwfl_Callbacks callbacks = {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
};

static debug_info_metadata debug_info = {0};

void unload_binary(binary_info *info) {
  if (!info)
    return;
  cs_close(&info->cs_handle);
  if (info->dwfl)
    dwfl_end(info->dwfl);
  if (info->map)
    munmap(info->map, info->size);
  free(info);
}

binary_info *load_binary(const char *filename) {
  binary_info *info = calloc(1, sizeof(binary_info));
  if (!info) {
    printf("Unable to calloc memroy for binary_info\n");
    exit(EXIT_FAILURE);
  }

  // initialize Capstone
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &info->cs_handle) != CS_ERR_OK) {
    fprintf(stderr, "Failed to initialize Capstone\n");
    free(info);
    exit(EXIT_FAILURE);
    return NULL;
  }

  // open the file
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    cs_close(&info->cs_handle);
    // invalid file binary provided, or in accessible. We should
    // still gracefully continue parsing everything else, rather than
    // failing the report generation.
    printf("nonfatal error. continuing...\n");
    free(info);
    return NULL;
  }

  // get file size
  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    cs_close(&info->cs_handle);
    free(info);
    exit(EXIT_FAILURE);
    return NULL;
  }
  info->size = st.st_size;

  // map file into memory
  info->map = mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (info->map == MAP_FAILED) {
    perror("mmap");
    close(fd);
    cs_close(&info->cs_handle);
    free(info);
    return NULL;
  }
  close(fd);

  // get ELF header
  info->ehdr = (Elf64_Ehdr *)info->map;
  if (memcmp(info->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "Not an ELF file\n");
    goto error;
  }

  // get section headers
  info->shdr = (Elf64_Shdr *)((char *)info->map + info->ehdr->e_shoff);

  // get section header string table
  info->shstrtab =
      (char *)info->map + info->shdr[info->ehdr->e_shstrndx].sh_offset;

  // find important sections
  for (int i = 0; i < info->ehdr->e_shnum; i++) {
    char *section_name = info->shstrtab + info->shdr[i].sh_name;

    if (strcmp(section_name, ".text") == 0) {
      info->text_section = (char *)info->map + info->shdr[i].sh_offset;
      info->text_addr = info->shdr[i].sh_addr;
      info->text_size = info->shdr[i].sh_size;
    } else if (strcmp(section_name, ".symtab") == 0) {
      info->symtab = (Elf64_Sym *)((char *)info->map + info->shdr[i].sh_offset);
      info->sym_count = info->shdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (strcmp(section_name, ".strtab") == 0) {
      info->strtab = (char *)info->map + info->shdr[i].sh_offset;
    }
  }

  // initialize DWARF debug info
  info->dwfl = dwfl_begin(&callbacks);
  if (info->dwfl == NULL) {
    fprintf(stderr, "Failed to initialize DWARF reader\n");
    goto error;
  }

  // load debug info for the binary
  dwfl_report_begin(info->dwfl);
  Dwfl_Module *module =
      dwfl_report_elf(info->dwfl, filename, filename, -1, 0, false);
  dwfl_report_end(info->dwfl, NULL, NULL);

  if (!module) {
    fprintf(stderr, "Failed to load debug info\n");
    goto error;
  }

  return info;

error:
  unload_binary(info);
  exit(EXIT_FAILURE);
  return NULL;
}

void cleanup_debug_info(void) {
  if (debug_info.elf_data != NULL) {
    munmap(debug_info.elf_data, debug_info.elf_size);
  }
  if (debug_info.dwfl != NULL) {
    dwfl_end(debug_info.dwfl);
  }
  cs_close(debug_info.cs_handle);
}

void process_branch_file(const char *filename, branch_entry *entries,
                         int *count) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    printf("Error opening branch file %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  char line[MAX_LINE];
  *count = 0;

  // skip header
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return;
  }

  while (fgets(line, sizeof(line), fp) && *count < MAX_ENTRIES) {
    branch_entry *entry = &entries[*count];
    int result = sscanf(line, "%[^,],%lx,%d,%d,%d,%d,%d,%d,%d", entry->filename,
                        &entry->offset, &entry->retired_insts,
                        &entry->not_taken_branches, &entry->mispredicted,
                        &entry->total_latency, &entry->issue_latency,
                        &entry->saturated, &entry->branch_type);

    if (result == 9) {
      (*count)++;
    }
  }
  fclose(fp);
}

void process_completion_file(const char *filename, completion_entry *entries,
                             int *count) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    printf("Error opening completion file %s: %s\n", filename, strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  char line[MAX_LINE];
  *count = 0;

  // skip header
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return;
  }

  while (fgets(line, sizeof(line), fp) && *count < MAX_ENTRIES) {
    completion_entry *entry = &entries[*count];
    int result = sscanf(
        line,
        "%[^,],%lx,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
        "%d",
        entry->filename, &entry->offset, &entry->retired_insts,
        &entry->total_latency, &entry->issue_latency,
        &entry->translation_latency, &entry->l1_bins[0], &entry->l1_bins[1],
        &entry->l1_bins[2], &entry->l1_bins[3], &entry->l2_bins[0],
        &entry->l2_bins[1], &entry->l2_bins[2], &entry->l2_bins[3],
        &entry->l3_bins[0], &entry->l3_bins[1], &entry->l3_bins[2],
        &entry->l3_bins[3], &entry->dram_bins[0], &entry->dram_bins[1],
        &entry->dram_bins[2], &entry->dram_bins[3], &entry->saturated);

    if (result == 23) {
      (*count)++;
    }
  }
  fclose(fp);
}

char *get_line_at_line_number(const char *filename, int target_line) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    return "???\0";
  }

  char *line = malloc(MAX_LINE_LENGTH);
  if (!line) {
    fclose(file);
    perror("Memory allocation failed");
    return NULL;
  }

  // Read lines until we reach the target line number
  int current_line = 1;
  while (current_line < target_line) {
    if (fgets(line, MAX_LINE_LENGTH, file) == NULL) {
      // Reached EOF before target line
      fclose(file);
      free(line);
      return NULL;
    }
    current_line++;
  }

  // Read the target line
  if (fgets(line, MAX_LINE_LENGTH, file) == NULL) {
    fclose(file);
    free(line);
    return NULL;
  }

  // Remove newline character if present
  size_t len = strlen(line);
  if (len > 0 && line[len - 1] == '\n') {
    line[len - 1] = '\0';
  }

  fclose(file);
  return line;
}

void get_source_info(binary_info *info, uint64_t addr, char **filename,
                     int *line) {
  *filename = NULL;
  *line = 0;

  Dwfl_Module *module = dwfl_addrmodule(info->dwfl, addr);
  if (!module)
    return;

  Dwfl_Line *line_info = dwfl_getsrc(info->dwfl, addr);
  if (line_info) {
    *filename = strdup(dwfl_lineinfo(line_info, NULL, line, NULL, NULL, NULL));
  }
}

char *get_absolute_path(const char *base_path, const char *relative_path) {
  if (!base_path || !relative_path) {
    return NULL;
  }

  // If relative_path is absolute (starts with '/'), just return a copy of it
  if (relative_path[0] == '/') {
    return strdup(relative_path);
  }

  // Get the directory part of base_path
  const char *last_slash = strrchr(base_path, '/');
  char *base_dir;

  if (!last_slash) {
    base_dir = strdup("./");
  } else {
    size_t dir_len = last_slash - base_path + 1;
    base_dir = malloc(dir_len + 1);
    if (!base_dir) {
      return NULL;
    }
    strncpy(base_dir, base_path, dir_len);
    base_dir[dir_len] = '\0';
  }

  if (!base_dir) {
    return NULL;
  }

  // Remove any "./" from the beginning of relative_path
  while (relative_path[0] == '.' && relative_path[1] == '/') {
    relative_path += 2;
  }

  char *full_path = malloc(PATH_MAX);
  if (!full_path) {
    free(base_dir);
    return NULL;
  }

  if (snprintf(full_path, PATH_MAX, "%s%s", base_dir, relative_path) >=
      PATH_MAX) {
    // Path too long
    free(base_dir);
    free(full_path);
    return NULL;
  }

  // Clean up any double slashes
  char *src = full_path;
  char *dst = full_path;
  char prev = '\0';

  while (*src) {
    if (*src == '/' && prev == '/') {
      src++;
      continue;
    }
    prev = *src;
    *dst++ = *src++;
  }
  *dst = '\0';

  free(base_dir);
  return full_path;
}

debug_info_data *get_asm(const char *filename, uint64_t offset) {
  binary_info *info = load_binary(filename);
  debug_info_data *dinfo = (debug_info_data *)malloc(sizeof(debug_info_data));
  memset(dinfo, 0, sizeof(debug_info_data));

  char location_with_line[151] = "???";
  char source_line[256] = "???";

  // allocate memory for assembly string
  dinfo->assembly = (char *)malloc(256);
  dinfo->source_file_line = (char *)malloc(256);
  if (!dinfo->assembly || !dinfo->source_file_line) {
    free(dinfo->assembly);
    free(dinfo->source_file_line);
    free(dinfo);
    return NULL;
  }

  snprintf(dinfo->source_file_line, sizeof(dinfo->source_file_line), "%s",
           "???");
  snprintf(dinfo->assembly, sizeof(dinfo->assembly), "%s", "???");

  if (info) {
    // get source file information
    char *source_file;
    int line_number = 0;
    char *line_s;
    get_source_info(info, offset, &source_file, &line_number);
    if (source_file) {
      char *full_path = get_absolute_path(filename, source_file);
      if (full_path) {
        snprintf(location_with_line, sizeof(location_with_line), "%s:%d",
                 full_path, line_number);
        line_s = get_line_at_line_number(full_path, line_number);
        free(full_path);
      } else {
        snprintf(location_with_line, sizeof(location_with_line), "%s:%d",
                 source_file, line_number);
        line_s = "???\0";
      }

      // get source line
      dinfo->line = line_s;
    } else {
      // if no source file is found, use binary with offset
      snprintf(location_with_line, sizeof(location_with_line), "%s:0x%lx",
               filename, offset);
    }

    strncpy(dinfo->source_file_line, location_with_line, 255);
    dinfo->source_file_line[255] = '\0';

    if (offset >= info->text_addr &&
        offset < info->text_addr + info->text_size) {
      uint64_t roffset = offset - info->text_addr;
      cs_insn *insn;
      size_t count =
          cs_disasm(info->cs_handle, (uint8_t *)info->text_section + roffset, 4,
                    offset, 1, &insn);

      if (count > 0) {
        char temp_assembly[256];
        snprintf(temp_assembly, sizeof(temp_assembly), "%s %s",
                 insn[0].mnemonic, insn[0].op_str);

        // replace commas with spaces
        for (char *p = temp_assembly; *p; p++) {
          if (*p == ',')
            *p = ' ';
        }

        strncpy(dinfo->assembly, temp_assembly, 255);
        dinfo->assembly[255] = '\0';

        cs_free(insn, count);
      }
    }
  }

  return dinfo;
}

char *get_function_name(binary_info *info, uint64_t addr) {
  if (!info || !info->symtab || !info->strtab)
    return NULL;

  for (int i = 0; i < info->sym_count; i++) {
    if (ELF64_ST_TYPE(info->symtab[i].st_info) == STT_FUNC) {
      if (addr >= info->symtab[i].st_value &&
          addr < info->symtab[i].st_value + info->symtab[i].st_size) {
        return strdup(info->strtab + info->symtab[i].st_name);
      }
    }
  }
  return NULL;
}

// comparison function for sorting by execution latency
int compare_exec_latency(const void *a, const void *b) {
  const completion_entry *ea = (const completion_entry *)a;
  const completion_entry *eb = (const completion_entry *)b;
  return (eb->total_latency - eb->issue_latency - eb->translation_latency) -
         (ea->total_latency - ea->issue_latency - ea->translation_latency);
}

void generate_exec_latency_view(completion_entry *completions,
                                int completion_count) {
  REPORT_FILE_PATH("exec_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    fprintf("Error creating exec_latency_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp,
          "Avg Exec Latency,Count,Saturated,Location,Line,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(completion_entry),
        compare_exec_latency);

  // process completion entries
  // assuming you have a binary_info struct for each file

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    binary_info *binary_info = load_binary(completions[i].filename);
    debug_info_data dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s,%s\n",
            (double)(completions[i].total_latency -
                     completions[i].issue_latency -
                     completions[i].translation_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, dinfo.line,
            function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!dinfo.line)
      free(dinfo.line);
    if (!function_name)
      free(function_name);

    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_issue_latency(const void *a, const void *b) {
  const completion_entry *ea = (const completion_entry *)a;
  const completion_entry *eb = (const completion_entry *)b;
  return (eb->issue_latency) - (ea->issue_latency);
}

void generate_issue_latency_view(completion_entry *completions,
                                 int completion_count) {
  REPORT_FILE_PATH("issue_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating issue_latency_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(
      fp,
      "Avg Issue Latency,Count,Saturated,Location,Line,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(completion_entry),
        compare_issue_latency);

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    binary_info *binary_info = load_binary(completions[i].filename);
    debug_info_data dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s,%s\n",
            (double)(completions[i].issue_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, dinfo.line,
            function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!dinfo.line)
      free(dinfo.line);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_x_latency(const void *a, const void *b) {
  const completion_entry *ea = (const completion_entry *)a;
  const completion_entry *eb = (const completion_entry *)b;
  return (eb->translation_latency) - (ea->translation_latency);
}

void generate_x_latency_view(completion_entry *completions,
                             int completion_count) {
  REPORT_FILE_PATH("x_lat_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating x_lat_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp,
          "Avg X Latency,Count,Saturated,Location,Line,Function,Assembly\n");

  // sort completions by execution latency
  qsort(completions, completion_count, sizeof(completion_entry),
        compare_x_latency);

  // process completion entries
  for (int i = 0; i < MIN(completion_count, PROCESS_LIMIT); i++) {
    binary_info *binary_info = load_binary(completions[i].filename);
    debug_info_data dinfo =
        *(get_asm(completions[i].filename, completions[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, completions[i].offset);

    fprintf(fp, "%.2f,%d,%d,%s,%s,%s,%s\n",
            (double)(completions[i].translation_latency) /
                completions[i].retired_insts,
            completions[i].retired_insts, completions[i].saturated,
            dinfo.source_file_line, dinfo.line,
            function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!dinfo.line)
      free(dinfo.line);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

// comparison function for sorting by execution latency
int compare_branch(const void *a, const void *b) {
  const branch_entry *ea = (const branch_entry *)a;
  const branch_entry *eb = (const branch_entry *)b;
  return (eb->total_latency) - (ea->total_latency);
}
void generate_branch_view(branch_entry *entries, int count) {
  REPORT_FILE_PATH("branch_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    printf("Error creating branch_view.csv: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
    return;
  }

  fprintf(fp, "Type,Count,Avg_Total_Lat,Avg_Issue_Lat,Not_Taken,Mispredicted,"
              "Saturated,Location,Line,Function,Assembly\n");

  qsort(entries, count, sizeof(branch_entry), compare_branch);

  for (int i = 0; i < MIN(count, PROCESS_LIMIT); i++) {
    binary_info *binary_info = load_binary(entries[i].filename);
    debug_info_data dinfo = *(get_asm(entries[i].filename, entries[i].offset));

    // get function name
    char *function_name = get_function_name(binary_info, entries[i].offset);

    fprintf(fp, "%s,%d,%.2f,%.2f,%d,%d,%d,%s,%s,%s,%s\n",
            entries[i].branch_type == 0x01 ? "COND" : "IND",
            entries[i].retired_insts,
            ((double)entries[i].total_latency / entries[i].retired_insts),
            ((double)entries[i].issue_latency / entries[i].retired_insts),
            entries[i].not_taken_branches, entries[i].mispredicted,
            entries[i].saturated, dinfo.source_file_line, dinfo.line,
            function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!dinfo.line)
      free(dinfo.line);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

void generate_completion_view(completion_entry *entries, int count) {
  REPORT_FILE_PATH("completion_node_view");
  FILE *fp = fopen(filepath, "w");
  if (!fp)
    return;

  qsort(entries, count, sizeof(completion_entry), compare_exec_latency);

  fprintf(
      fp,
      "L1 (%),L1 bins (%% | %% | %% | %%),L2 (%),L2 bins (%% | %% | %% | %%),"
      "L3 (%),L3 bins (%% | %% | %% | %%),DRAM (%),DRAM bins (%% | %% | %% | "
      "%%),"
      "Location,Line,Function,Assembly\n");

  for (int i = 0; i < MIN(count, PROCESS_LIMIT); i++) {
    binary_info *binary_info = load_binary(entries[i].filename);
    debug_info_data dinfo = *(get_asm(entries[i].filename, entries[i].offset));

    char *function_name = get_function_name(binary_info, entries[i].offset);

    int l1_total = entries[i].l1_bins[0] + entries[i].l1_bins[1] +
                   entries[i].l1_bins[2] + entries[i].l1_bins[3];
    int l2_total = entries[i].l2_bins[0] + entries[i].l2_bins[1] +
                   entries[i].l2_bins[2] + entries[i].l2_bins[3];
    int l3_total = entries[i].l3_bins[0] + entries[i].l3_bins[1] +
                   entries[i].l3_bins[2] + entries[i].l3_bins[3];
    int dram_total = entries[i].dram_bins[0] + entries[i].dram_bins[1] +
                     entries[i].dram_bins[2] + entries[i].dram_bins[3];

    int grand_total = l1_total + l2_total + l3_total + dram_total;

    if (grand_total == 0) {
      grand_total = 1; // this will result in 0% for all categories
    }

    double l1_percent = (double)l1_total / grand_total * 100.0;
    double l2_percent = (double)l2_total / grand_total * 100.0;
    double l3_percent = (double)l3_total / grand_total * 100.0;
    double dram_percent = (double)dram_total / grand_total * 100.0;

    // calculate bin percentages
    double l1_bin_percents[4], l2_bin_percents[4], l3_bin_percents[4],
        dram_bin_percents[4];

    for (int j = 0; j < 4; j++) {
      l1_bin_percents[j] =
          l1_total > 0 ? (double)entries[i].l1_bins[j] / l1_total * 100.0 : 0.0;
      l2_bin_percents[j] =
          l2_total > 0 ? (double)entries[i].l2_bins[j] / l2_total * 100.0 : 0.0;
      l3_bin_percents[j] =
          l3_total > 0 ? (double)entries[i].l3_bins[j] / l3_total * 100.0 : 0.0;
      dram_bin_percents[j] =
          dram_total > 0 ? (double)entries[i].dram_bins[j] / dram_total * 100.0
                         : 0.0;
    }

    fprintf(fp,
            "%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | "
            "%.2f,%.2f,%.2f | %.2f | %.2f | %.2f,%.2f,%.2f | %.2f | %.2f | "
            "%.2f,%s,%s,%s,%s\n",
            l1_percent, l1_bin_percents[0], l1_bin_percents[1],
            l1_bin_percents[2], l1_bin_percents[3], l2_percent,
            l2_bin_percents[0], l2_bin_percents[1], l2_bin_percents[2],
            l2_bin_percents[3], l3_percent, l3_bin_percents[0],
            l3_bin_percents[1], l3_bin_percents[2], l3_bin_percents[3],
            dram_percent, dram_bin_percents[0], dram_bin_percents[1],
            dram_bin_percents[2], dram_bin_percents[3], dinfo.source_file_line,
            dinfo.line, function_name ? function_name : "???", dinfo.assembly);

    if (!dinfo.source_file_line)
      free(dinfo.source_file_line);
    if (!dinfo.assembly)
      free(dinfo.assembly);
    if (!dinfo.line)
      free(dinfo.line);
    if (!function_name)
      free(function_name);
    unload_binary(binary_info);
  }

  fclose(fp);
}

void build_report() {
  branch_entry branch_entries[MAX_ENTRIES];
  completion_entry completion_entries[MAX_ENTRIES];
  int branch_count = 0, completion_count = 0;

  const char *report_dir = get_hotline_dir();
  if (report_dir == NULL) {
    fprintf(stderr, "Failed to get hotline report directory\n");
    return 1;
  }

  char branch_file_path[MAX_LINE];
  char completion_file_path[MAX_LINE];

  snprintf(branch_file_path, sizeof(branch_file_path),
           "%s/spe_hotline_branches.bin", report_dir);
  snprintf(completion_file_path, sizeof(completion_file_path),
           "%s/spe_hotline_loads.bin", report_dir);

  // process input files
  process_branch_file(branch_file_path, branch_entries, &branch_count);

  process_completion_file(completion_file_path, completion_entries,
                          &completion_count);

  // generate views
  generate_exec_latency_view(completion_entries, completion_count);
  generate_issue_latency_view(completion_entries, completion_count);
  generate_x_latency_view(completion_entries, completion_count);
  generate_branch_view(branch_entries, branch_count);
  generate_completion_view(completion_entries, completion_count);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>
#include <capstone/capstone.h>

#define MAX_LINE_LENGTH 1024
#define MAX_FILENAME_LENGTH 256
#define INITIAL_CAPACITY 10
// #define NUM_REPORT 100

#ifndef NUM_REPORT
#define NUM_REPORT 100
#endif 

#ifndef HOTLINE_DIR
#define HOTLINE_DIR "/home/ubuntu/hotline"
#endif

#define PATH_MAX 512

#define AUX_RECORD_B_COND 0x01

#define MIN(a, b) ((a) < (b) ? (a) : (b))

extern const char* get_hotline_dir();

struct bin
{
    uint64_t bin1;
    uint64_t bin2;
    uint64_t bin3;
    uint64_t bin4;
};

struct memop_data
{
    char *filename;
    uint64_t offset;
    uint64_t retired_insts;
    uint64_t total_latency;
    uint64_t issue_latency;
    uint64_t translation_latency;
    struct bin l1, l2, l3, dram;
    uint64_t saturated;
};

typedef struct
{
    void *map;
    size_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    char *shstrtab;
    Elf64_Sym *symtab;
    char *strtab;
    int sym_count;
    void *text_section;
    uint64_t text_addr;
    size_t text_size;
    Dwfl *dwfl;
    csh cs_handle; // Capstone handle
} BinaryInfo;

static const Dwfl_Callbacks callbacks = {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
};

void unload_binary(BinaryInfo *info)
{
    if (!info)
        return;
    cs_close(&info->cs_handle);
    if (info->dwfl)
        dwfl_end(info->dwfl);
    if (info->map)
        munmap(info->map, info->size);
    free(info);
}

BinaryInfo *load_binary(const char *filename)
{
    BinaryInfo *info = calloc(1, sizeof(BinaryInfo));
    if (!info)
        return NULL;

    // Initialize Capstone
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &info->cs_handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Failed to initialize Capstone\n");
        free(info);
        return NULL;
    }

    // Open the file
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        cs_close(&info->cs_handle);
        free(info);
        return NULL;
    }

    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        perror("fstat");
        close(fd);
        cs_close(&info->cs_handle);
        free(info);
        return NULL;
    }
    info->size = st.st_size;

    // Map file into memory
    info->map = mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (info->map == MAP_FAILED)
    {
        perror("mmap");
        close(fd);
        cs_close(&info->cs_handle);
        free(info);
        return NULL;
    }
    close(fd);

    // Get ELF header
    info->ehdr = (Elf64_Ehdr *)info->map;
    if (memcmp(info->ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Not an ELF file\n");
        goto error;
    }

    // Get section headers
    info->shdr = (Elf64_Shdr *)((char *)info->map + info->ehdr->e_shoff);

    // Get section header string table
    info->shstrtab = (char *)info->map +
                     info->shdr[info->ehdr->e_shstrndx].sh_offset;

    // Find important sections
    for (int i = 0; i < info->ehdr->e_shnum; i++)
    {
        char *section_name = info->shstrtab + info->shdr[i].sh_name;

        if (strcmp(section_name, ".text") == 0)
        {
            info->text_section = (char *)info->map + info->shdr[i].sh_offset;
            info->text_addr = info->shdr[i].sh_addr;
            info->text_size = info->shdr[i].sh_size;
        }
        else if (strcmp(section_name, ".symtab") == 0)
        {
            info->symtab = (Elf64_Sym *)((char *)info->map +
                                         info->shdr[i].sh_offset);
            info->sym_count = info->shdr[i].sh_size / sizeof(Elf64_Sym);
        }
        else if (strcmp(section_name, ".strtab") == 0)
        {
            info->strtab = (char *)info->map + info->shdr[i].sh_offset;
        }
    }

    // Initialize DWARF debug info
    info->dwfl = dwfl_begin(&callbacks);
    if (info->dwfl == NULL)
    {
        fprintf(stderr, "Failed to initialize DWARF reader\n");
        goto error;
    }

    // Load debug info for the binary
    dwfl_report_begin(info->dwfl);
    Dwfl_Module *module = dwfl_report_elf(
        info->dwfl,
        filename,
        filename,
        -1,
        0,
        false);
    dwfl_report_end(info->dwfl, NULL, NULL);

    if (!module)
    {
        fprintf(stderr, "Failed to load debug info\n");
        goto error;
    }

    return info;

error:
    unload_binary(info);
    return NULL;
}

char *get_function_name(BinaryInfo *info, uint64_t addr)
{
    if (!info || !info->symtab || !info->strtab)
        return NULL;

    for (int i = 0; i < info->sym_count; i++)
    {
        if (ELF64_ST_TYPE(info->symtab[i].st_info) == STT_FUNC)
        {
            if (addr >= info->symtab[i].st_value &&
                addr < info->symtab[i].st_value + info->symtab[i].st_size)
            {
                return strdup(info->strtab + info->symtab[i].st_name);
            }
        }
    }
    return NULL;
}

void get_source_info(BinaryInfo *info, uint64_t addr,
                     char **filename, int *line)
{
    *filename = NULL;
    *line = 0;

    Dwfl_Module *module = dwfl_addrmodule(info->dwfl, addr);
    if (!module)
        return;

    Dwfl_Line *line_info = dwfl_getsrc(info->dwfl, addr);
    if (line_info)
    {
        *filename = strdup(dwfl_lineinfo(line_info, NULL, line,
                                         NULL, NULL, NULL));
    }
}

void process_address(BinaryInfo *info, uint64_t addr)
{
    if (!info)
        return;

    char *func_name = get_function_name(info, addr);
    char *source_file;
    int line_number;

    printf("Address: 0x%lx\n", addr);
    if (func_name)
    {
        printf("Function: %s\n", func_name);
        free(func_name);
    }

    // Get source line information
    get_source_info(info, addr, &source_file, &line_number);
    if (source_file)
    {
        FILE *f = fopen(source_file, "r");
        if (f)
        {
            char line[256];
            int current_line = 0;
            while (fgets(line, sizeof(line), f) && current_line < line_number)
            {
                current_line++;
            }
            if (current_line == line_number)
            {
                line[strcspn(line, "\n")] = 0;
                printf("Source: %s:%d\n", source_file, line_number);
                printf("Code: %s\n", line);
            }
            fclose(f);
        }
        else
        {
            printf("Source: %s:%d (file not found)\n", source_file, line_number);
        }
        free(source_file);
    }

    if (addr >= info->text_addr &&
        addr < info->text_addr + info->text_size)
    {

        uint64_t offset = addr - info->text_addr;

        // Print raw bytes
        printf("Raw bytes: ");
        for (int i = 0; i < 4 && offset + i < info->text_size; i++)
        {
            printf("%02x ", ((unsigned char *)info->text_section)[offset + i]);
        }
        printf("\n");

        // Disassemble using Capstone
        cs_insn *insn;
        size_t count = cs_disasm(info->cs_handle,
                                 (uint8_t *)info->text_section + offset,
                                 4, // Size of an ARM64 instruction
                                 addr,
                                 1, // Number of instructions to disassemble
                                 &insn);

        if (count > 0)
        {
            printf("Instruction: %s %s\n", insn[0].mnemonic, insn[0].op_str);
            cs_free(insn, count);
        }
        else
        {
            printf("Failed to disassemble instruction\n");
        }
    }
    printf("\n");
}

struct branch_data
{
    char *filename;
    uint64_t offset;
    uint64_t retired_insts;
    uint64_t not_taken_branches;
    uint64_t mispredicted;
    uint64_t total_latency;
    uint64_t issue_latency;
    uint64_t saturated;
    uint8_t branch_type;
};

// Add function to load branch data
size_t load_branch_data(struct branch_data **data)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "hotlines_branches.data");
    FILE *file = fopen(path, "r");
    if (!file)
    {
        perror("Error opening branch file");
        return 0;
    }

    size_t capacity = INITIAL_CAPACITY;
    size_t size = 0;
    *data = malloc(capacity * sizeof(struct branch_data));
    if (!*data)
    {
        perror("Memory allocation failed");
        fclose(file);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    // Skip header line
    fgets(line, MAX_LINE_LENGTH, file);

    while (fgets(line, MAX_LINE_LENGTH, file))
    {
        if (size >= capacity)
        {
            capacity *= 2;
            struct branch_data *temp = realloc(*data, capacity * sizeof(struct branch_data));
            if (!temp)
            {
                perror("Memory reallocation failed");
                for (size_t i = 0; i < size; i++)
                {
                    free((*data)[i].filename);
                }
                free(*data);
                *data = NULL;
                fclose(file);
                return 0;
            }
            *data = temp;
        }

        (*data)[size].filename = (char *)malloc(MAX_FILENAME_LENGTH * sizeof(char));
        if (!(*data)[size].filename)
        {
            perror("Memory allocation failed for filename");
            for (size_t i = 0; i < size; i++)
            {
                free((*data)[i].filename);
            }
            free(*data);
            *data = NULL;
            fclose(file);
            return 0;
        }

        if (sscanf(line, "%[^,],0x%" SCNx64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu8,
                   (*data)[size].filename,
                   &(*data)[size].offset,
                   &(*data)[size].retired_insts,
                   &(*data)[size].not_taken_branches,
                   &(*data)[size].mispredicted,
                   &(*data)[size].total_latency,
                   &(*data)[size].issue_latency,
                   &(*data)[size].saturated,
                   &(*data)[size].branch_type) == 9)
        {
            size++;
        }
        else
        {
            free((*data)[size].filename);
        }
    }

    fclose(file);
    return size;
}

// Add comparison function for branch data
int compare_branch_data(const void *a, const void *b)
{
    struct branch_data *data_a = (struct branch_data *)a;
    struct branch_data *data_b = (struct branch_data *)b;
    if (data_b->retired_insts > data_a->retired_insts)
        return 1;
    if (data_b->retired_insts < data_a->retired_insts)
        return -1;
    return 0;
}

// Add function to process branch data
void process_branch_data(struct branch_data *data, size_t num_entries, const char *output_filename)
{
    qsort(data, num_entries, sizeof(struct branch_data), compare_branch_data);

    FILE *output_file = fopen(output_filename, "w");
    if (!output_file)
    {
        perror("Error opening output file");
        return;
    }

    // Write header
    fprintf(output_file,
            "%-10s %-15s %-15s %-12s %-15s %-12s %-12s "
            "%-150s %-60s %-60s %-30s\n",
            "Type", "Avg_Exec_Lat", "Avg_Issue_Lat", "Count", "Not_Taken", "Mispredicted", "Saturated",
            "Location", "Function", "Source_Code", "Assembly");

    for (size_t i = 0; i < MIN(NUM_REPORT, num_entries) && i < num_entries; i++)
    {
        double avg_exec_lat = (double)(data[i].total_latency - data[i].issue_latency) / data[i].retired_insts;
        double avg_issue_lat = (double)data[i].issue_latency / data[i].retired_insts;

        fprintf(output_file,
                "%-10s %-15.2f %-15.2f %-12lu %-15lu %-12lu %-12lu ",
                (data[i].branch_type == AUX_RECORD_B_COND) ? "COND" : "IND",
                avg_exec_lat,
                avg_issue_lat,
                data[i].retired_insts,
                data[i].not_taken_branches,
                data[i].mispredicted,
                data[i].saturated);

        char location_with_line[151] = "unknown";
        BinaryInfo *info = load_binary(data[i].filename);
        if (info)
        {
            // Get source file information
            char *source_file;
            int line_number = 0;
            get_source_info(info, data[i].offset, &source_file, &line_number);
            if (source_file)
            {
                snprintf(location_with_line, sizeof(location_with_line), "%s:%d",
                         source_file, line_number);
                free(source_file);
            }
            else
            {
                // If no source file is found, use binary with offset
                snprintf(location_with_line, sizeof(location_with_line), "%s:0x%lx",
                         data[i].filename, data[i].offset);
            }

            fprintf(output_file, "%-150s ", location_with_line);

            // Get function name
            char *func_name = get_function_name(info, data[i].offset);
            fprintf(output_file, "%-60s ", func_name ? func_name : "unknown");
            if (func_name)
                free(func_name);

            // Get source line
            char source_line[61] = "unknown";
            get_source_info(info, data[i].offset, &source_file, &line_number);
            if (source_file)
            {
                FILE *f = fopen(source_file, "r");
                if (f)
                {
                    char line[256];
                    int current_line = 0;
                    while (fgets(line, sizeof(line), f) && current_line < line_number)
                    {
                        current_line++;
                    }
                    if (current_line == line_number)
                    {
                        line[strcspn(line, "\n")] = 0;
                        strncpy(source_line, line, sizeof(source_line) - 1);
                        source_line[sizeof(source_line) - 1] = '\0';
                    }
                    fclose(f);
                }
                free(source_file);
            }
            fprintf(output_file, "%-60s ", source_line);

            // Get assembly instruction
            char assembly[31] = "unknown";
            if (data[i].offset >= info->text_addr &&
                data[i].offset < info->text_addr + info->text_size)
            {

                uint64_t offset = data[i].offset - info->text_addr;
                cs_insn *insn;
                size_t count = cs_disasm(info->cs_handle,
                                         (uint8_t *)info->text_section + offset,
                                         4,
                                         data[i].offset,
                                         1,
                                         &insn);

                if (count > 0)
                {
                    snprintf(assembly, sizeof(assembly), "%s %s",
                             insn[0].mnemonic, insn[0].op_str);
                    cs_free(insn, count);
                }
            }
            fprintf(output_file, "%-30s", assembly);

            unload_binary(info);
        }
        else
        {
            fprintf(output_file, "%-150s %-60s %-60s %-30s",
                    data[i].filename, "unknown", "unknown", "unknown");
        }
        fprintf(output_file, "\n");
    }

    fclose(output_file);
    printf("\t> Branch data has been written to %s\n", output_filename);
}

size_t load_memop_data(struct memop_data **data)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "hotlines_loads.data");
    FILE *file = fopen(path, "r");
    if (!file)
    {
        perror("Error opening file");
        return 0;
    }

    size_t capacity = INITIAL_CAPACITY;
    size_t size = 0;
    *data = malloc(capacity * sizeof(struct memop_data));
    if (!*data)
    {
        perror("Memory allocation failed");
        fclose(file);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    // Skip header line
    fgets(line, MAX_LINE_LENGTH, file);

    while (fgets(line, MAX_LINE_LENGTH, file))
    {
        if (size >= capacity)
        {
            capacity *= 2;
            struct memop_data *temp = realloc(*data, capacity * sizeof(struct memop_data));
            if (!temp)
            {
                perror("Memory reallocation failed");
                for (size_t i = 0; i < size; i++)
                {
                    free((*data)[i].filename);
                }
                free(*data);
                *data = NULL;
                fclose(file);
                return 0;
            }
            *data = temp;
        }

        // Allocate memory for filename
        (*data)[size].filename = (char *)malloc(MAX_FILENAME_LENGTH * sizeof(char));
        if (!(*data)[size].filename)
        {
            perror("Memory allocation failed for filename");
            // Free already allocated filenames
            for (size_t i = 0; i < size; i++)
            {
                free((*data)[i].filename);
            }
            free(*data);
            *data = NULL;
            fclose(file);
            return 0;
        }

        // Parse the line using sscanf
        if (sscanf(line, "%[^,],0x%" SCNx64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64,
                   (*data)[size].filename,
                   &(*data)[size].offset,
                   &(*data)[size].retired_insts,
                   &(*data)[size].total_latency,
                   &(*data)[size].issue_latency,
                   &(*data)[size].translation_latency,
                   &(*data)[size].l1.bin1,
                   &(*data)[size].l1.bin2,
                   &(*data)[size].l1.bin3,
                   &(*data)[size].l1.bin4,
                   &(*data)[size].l2.bin1,
                   &(*data)[size].l2.bin2,
                   &(*data)[size].l2.bin3,
                   &(*data)[size].l2.bin4,
                   &(*data)[size].l3.bin1,
                   &(*data)[size].l3.bin2,
                   &(*data)[size].l3.bin3,
                   &(*data)[size].l3.bin4,
                   &(*data)[size].dram.bin1,
                   &(*data)[size].dram.bin2,
                   &(*data)[size].dram.bin3,
                   &(*data)[size].dram.bin4,
                   &(*data)[size].saturated) == 23)
        { // Check if all fields were read
            size++;
        }
        else
        {
            free((*data)[size].filename); // Free the filename memory if parsing failed
        }
    }

    fclose(file);
    return size;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Comparison function for qsort
int compare_memop_data(const void *a, const void *b)
{
    struct memop_data *data_a = (struct memop_data *)a;
    struct memop_data *data_b = (struct memop_data *)b;
    if (data_b->retired_insts > data_a->retired_insts)
        return 1;
    if (data_b->retired_insts < data_a->retired_insts)
        return -1;
    return 0;
}

void process_memop_data(struct memop_data *data, size_t num_entries, const char *output_filename)
{
    // Sort the data by count (retired_insts) in descending order
    qsort(data, num_entries, sizeof(struct memop_data), compare_memop_data);

    FILE *output_file = fopen(output_filename, "w");
    if (!output_file)
    {
        perror("Error opening output file");
        return;
    }

    // Write aligned header with proper spacing
    fprintf(output_file,
            "%-15s %-15s %-12s %-12s %-9s "
            "%-200s " // Completion Distribution (fixed width for alignment)
            "%-150s %-60s %-60s %-30s\n",
            "Avg_Exec_Lat", "Avg_Issue_Lat", "Avg_X_Lat", "Count", "Saturated",
            "Completion_Distribution", "Location", "Function", "Source_Code", "Assembly");

    for (size_t i = 0; i < MIN(num_entries, NUM_REPORT); i++)
    {
        double avg_exec_lat = (double)(data[i].total_latency - data[i].issue_latency - data[i].translation_latency) / data[i].retired_insts;
        double avg_issue_lat = (double)data[i].issue_latency / data[i].retired_insts;
        double avg_x_lat = (double)data[i].translation_latency / data[i].retired_insts;

        uint64_t l1_total = data[i].l1.bin1 + data[i].l1.bin2 + data[i].l1.bin3 + data[i].l1.bin4;
        uint64_t l2_total = data[i].l2.bin1 + data[i].l2.bin2 + data[i].l2.bin3 + data[i].l2.bin4;
        uint64_t l3_total = data[i].l3.bin1 + data[i].l3.bin2 + data[i].l3.bin3 + data[i].l3.bin4;
        uint64_t dram_total = data[i].dram.bin1 + data[i].dram.bin2 + data[i].dram.bin3 + data[i].dram.bin4;
        uint64_t total = l1_total + l2_total + l3_total + dram_total;

        //     // Format the data line with consistent spacing
        fprintf(output_file,
                "%-15.2f %-15.2f %-12.2f %-12lu %-9lu ",
                avg_exec_lat,
                avg_issue_lat,
                avg_x_lat,
                data[i].retired_insts,
                data[i].saturated);

        // Format completion distribution with consistent width
        char distribution[201];
        snprintf(distribution, sizeof(distribution),
                 "L1:[%5.1f%% | %6.1f%% %6.1f%% %6.1f%% %6.1f%%] "
                 "L2:[%5.1f%% | %6.1f%% %6.1f%% %6.1f%% %6.1f%%] "
                 "L3:[%5.1f%% | %6.1f%% %6.1f%% %6.1f%% %6.1f%%] "
                 "DRAM:[%5.1f%% | %6.1f%% %6.1f%% %6.1f%% %6.1f%%]",
                 100.0 * l1_total / total,
                 100.0 * data[i].l1.bin1 / total,
                 100.0 * data[i].l1.bin2 / total,
                 100.0 * data[i].l1.bin3 / total,
                 100.0 * data[i].l1.bin4 / total,
                 100.0 * l2_total / total,
                 100.0 * data[i].l2.bin1 / total,
                 100.0 * data[i].l2.bin2 / total,
                 100.0 * data[i].l2.bin3 / total,
                 100.0 * data[i].l2.bin4 / total,
                 100.0 * l3_total / total,
                 100.0 * data[i].l3.bin1 / total,
                 100.0 * data[i].l3.bin2 / total,
                 100.0 * data[i].l3.bin3 / total,
                 100.0 * data[i].l3.bin4 / total,
                 100.0 * dram_total / total,
                 100.0 * data[i].dram.bin1 / total,
                 100.0 * data[i].dram.bin2 / total,
                 100.0 * data[i].dram.bin3 / total,
                 100.0 * data[i].dram.bin4 / total);
        fprintf(output_file, "%-200s ", distribution);

        char location_with_line[151] = "unknown";
        BinaryInfo *info = load_binary(data[i].filename);
        if (info)
        {
            // Get source file information
            char *source_file;
            int line_number = 0;
            get_source_info(info, data[i].offset, &source_file, &line_number);
            if (source_file)
            {
                snprintf(location_with_line, sizeof(location_with_line), "%s:%d",
                         source_file, line_number);
                free(source_file);
            }
            else
            {
                // If no source file is found, use binary with offset
                snprintf(location_with_line, sizeof(location_with_line), "%s:0x%lx",
                         data[i].filename, data[i].offset);
            }

            fprintf(output_file, "%-150s ", location_with_line);

            // Rest of the binary info processing
            char *func_name = get_function_name(info, data[i].offset);
            fprintf(output_file, "%-60s ", func_name ? func_name : "unknown");
            if (func_name)
                free(func_name);

            char source_line[61] = "unknown";
            if (source_file)
            {
                FILE *f = fopen(source_file, "r");
                if (f)
                {
                    char line[256];
                    int current_line = 0;
                    while (fgets(line, sizeof(line), f) && current_line < line_number)
                    {
                        current_line++;
                    }
                    if (current_line == line_number)
                    {
                        line[strcspn(line, "\n")] = 0;
                        strncpy(source_line, line, sizeof(source_line) - 1);
                        source_line[sizeof(source_line) - 1] = '\0';
                    }
                    fclose(f);
                }
            }
            fprintf(output_file, "%-60s ", source_line);

            char assembly[31] = "unknown";
            if (data[i].offset >= info->text_addr &&
                data[i].offset < info->text_addr + info->text_size)
            {

                uint64_t offset = data[i].offset - info->text_addr;
                cs_insn *insn;
                size_t count = cs_disasm(info->cs_handle,
                                         (uint8_t *)info->text_section + offset,
                                         4,
                                         data[i].offset,
                                         1,
                                         &insn);

                if (count > 0)
                {
                    snprintf(assembly, sizeof(assembly), "%s %s",
                             insn[0].mnemonic, insn[0].op_str);
                    cs_free(insn, count);
                }
            }
            fprintf(output_file, "%-30s", assembly);

            unload_binary(info);
        }
        else
        {
            fprintf(output_file, "%-150s %-60s %-60s %-30s",
                    data[i].filename, "unknown", "unknown", "unknown");
        }
        fprintf(output_file, "\n");
    }

    fclose(output_file);
    printf("\t> Load data has been written to %s\n", output_filename);
}

int build_report()
{
    // Process memory operations data
    struct memop_data *memop_data = NULL;
    size_t num_memop_entries = load_memop_data(&memop_data);
    if (num_memop_entries > 0)
    {
        printf("\t> Successfully loaded %zu memory operation entries\n", num_memop_entries);
        char output_path[PATH_MAX];
        snprintf(output_path, sizeof(output_path), "%s/%s", get_hotline_dir(), "hotlines_loads.report");
        process_memop_data(memop_data, num_memop_entries, output_path);
        for (size_t i = 0; i < num_memop_entries; i++)
        {
            free(memop_data[i].filename);
        }
        free(memop_data);
    }

    // Process branch data
    struct branch_data *branch_data = NULL;
    size_t num_branch_entries = load_branch_data(&branch_data);
    if (num_branch_entries > 0)
    {
        printf("\t> Successfully loaded %zu branch entries\n", num_branch_entries);
        char output_path[PATH_MAX];
        snprintf(output_path, sizeof(output_path), "%s/%s", get_hotline_dir(), "hotlines_branches.report");
        process_branch_data(branch_data, num_branch_entries, output_path);  // Use output_path here
        for (size_t i = 0; i < num_branch_entries; i++)
        {
            free(branch_data[i].filename);
        }
        free(branch_data);
    }

    return 0;
}
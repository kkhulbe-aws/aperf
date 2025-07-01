#include "config.h"
#include "auxtrace.h"
#include "vm_spe_btree.h"
#include "btree.h"
#include "mmap_table.h"
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// global data structures independent of sessions
struct btree *vm_spe_tr;
char *global_filenames[MAX_FILENAMES];
size_t global_filename_count = 0;
struct pid_maps_table *mapping_table;

extern int build_report();

#ifndef PATH_MAX
#define PATH_MAX 512
#endif


/**
 * On every event loop:
 * 1. Loop through the AUX buffer, starting from where we left off on the previous loop
 * 2. Upgrade the timestamp of the session by iterating through the record buffer up
 *    to the timestamp right before the current AUX entry
 *    a. If it is PERF_RECORD_SWITCH_CPU_WIDE: if it is a switch out, update the current session pid
 *    b. If it is PERF_RECORD_MMAP2: update the mmap datastructures with the new mappings
 *    c. If it is PERF_RECORD_EXIT: clean out the mmap mappings for the corresponding pid
 * 
 * The tool is implemented with this two pointer mechanism rather than a min-heap because we observed
 * the CPU utilization overhead of the minheap is non-trivial, and can reach upwards of 9-11%, on worst-case
 * workloads. This mechanism has an observed worst-case of 2% and average of 1%, which motivates enabling it by 
 * default on APerf.
 *
 * Architecture:
 *
 * +---------------+---------------+
 * |               |               |
 * | Record Buffer |  Aux Buffer  |
 * |               |               |
 * +---------------+---------------+
 *                 ^
 *                 |
 * +---------+    +----------+    +-----------+
 * | Session |    |          |    | hotline   |
 * | current |----> Main loop<----+ B-Tree    |
 * |  PID    |    |          |    |           |
 * +---------+    +----------+    +-----------+
 *                     ^                |
 *                     |                |
 *                     |                v
 *                +---------+           |
 *                |         |           |
 *                |MMAPings |<----------+
 *                |         |
 *                +---------+
 *
 * The B-Tree is what aggregates all the statistics for the user. In order to do so, we need to know what
 * the current pid is (hence the PERF_RECORD_SWITCH_CPU_WIDE records), and a mapping structure for the virtual address
 * offsets. To ensure proper time ordering, everything is inserted into the heap, pulled out, and processed in the corresponding
 * data structures.
 * 
 * The tool maintains a legacy implementation using the min-heap, and can be swapped out for the two pointer method.
 */

const char *get_hotline_dir()
{
    const char *env_dir = getenv("HOTLINE_DIR");
    return env_dir ? env_dir : "";
}

const char *get_hotline_report_dir()
{
    const char *env_dir = getenv("HOTLINE_REPORT_DIR");
    return env_dir ? env_dir : "";
}


int get_hotline_verbose()
{
    return 1;
}

void print_progress_bar(int percentage)
{
    printf("\rProgress: [");
    for (int i = 0; i < 50; i++)
    {
        if (i < percentage / 2)
        {
            printf("=");
        }
        else
        {
            printf(" ");
        }
    }
    printf("] %d%%", percentage);
    fflush(stdout);
}

void signal_handler(int signum) {
    commit_to_file();
    exit(signum);
}

void commit_to_file()
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "spe_hotline_loads.bin");
    FILE *load_fp = fopen(path, "w");

    memset(path, 0, sizeof(char) * PATH_MAX);
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "spe_hotline_branches.bin");
    FILE *branch_fp = fopen(path, "w");

    if (!load_fp || !branch_fp)
    {
        fprintf(stderr, "Error opening output files: %s\n", strerror(errno));
        if (load_fp)
            fclose(load_fp);
        if (branch_fp)
            fclose(branch_fp);
        return;
    }

    // write headers
    fprintf(load_fp, "filename,offset,retired_insts,total_latency,issue_latency,translation_latency,"
                     "l1_bin1,l1_bin2,l1_bin3,l1_bin4,"
                     "l2_bin1,l2_bin2,l2_bin3,l2_bin4,"
                     "l3_bin1,l3_bin2,l3_bin3,l3_bin4,"
                     "dram_bin1,dram_bin2,dram_bin3,dram_bin4,saturated\n");

    fprintf(branch_fp, "filename,offset,retired_insts,not_taken_branches,mispredicted,total_latency,issue_latency,saturated,branch_type\n");

    struct btree_iter *iter = btree_iter_new(vm_spe_tr);
    bool ok = btree_iter_first(iter);
    while (ok)
    {
        struct vm_spe_btree_entry *entry = (struct vm_spe_btree_entry *)btree_iter_item(iter);

        if (entry->type == AUX_RECORD_LOAD)
        { // LOAD
            fprintf(load_fp, "%s,0x%lx,%lu,%lu,%lu,%lu,"
                             "%lu,%lu,%lu,%lu,"       // l1 bins
                             "%lu,%lu,%lu,%lu,"       // l2 bins
                             "%lu,%lu,%lu,%lu,"       // l3 bins
                             "%lu,%lu,%lu,%lu,%lu\n", // dram bins
                    global_filenames[entry->file_id],
                    entry->offset,
                    entry->retired_insts,
                    entry->total_latency,
                    entry->issue_latency,
                    entry->load_entry.x_latency,
                    entry->load_entry.l1.bin_1, entry->load_entry.l1.bin_2, entry->load_entry.l1.bin_3, entry->load_entry.l1.bin_4,
                    entry->load_entry.l2.bin_1, entry->load_entry.l2.bin_2, entry->load_entry.l2.bin_3, entry->load_entry.l2.bin_4,
                    entry->load_entry.l3.bin_1, entry->load_entry.l3.bin_2, entry->load_entry.l3.bin_3, entry->load_entry.l3.bin_4,
                    entry->load_entry.dram.bin_1, entry->load_entry.dram.bin_2, entry->load_entry.dram.bin_3, entry->load_entry.dram.bin_4,
                    entry->saturated_packets);
        }
        else if (entry->type == AUX_RECORD_BRANCH)
        {
            fprintf(branch_fp, "%s,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%x\n",
                    global_filenames[entry->file_id],
                    entry->offset,
                    entry->retired_insts,
                    entry->branch_entry.not_taken_branches,
                    entry->branch_entry.mispredicted,
                    entry->total_latency,
                    entry->issue_latency,
                    entry->saturated_packets, entry->branch_entry.branch_type);
        }

        ok = btree_iter_next(iter);
    }
    btree_iter_free(iter);
    btree_free(vm_spe_tr);

    fclose(load_fp);
    fclose(branch_fp);

    free_pid_maps_table(mapping_table);
}

int hotline_main(int argc, char *argv[])
{
    struct arg_config config;
    parse_arguments(argc, argv, &config);
    struct arm_spe_pmu pmus[config.num_cpu];

    struct cpu_session sessions[config.num_cpu];

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Error: cannot handle SIGTERM");
        return 1;
    }

    configure_all_pmus(pmus, &config);
    reset_all_pmus(pmus, &config);
    enable_all_pmus(pmus, &config);
    struct spe_stats stats;
    memset(&stats, 0, sizeof(struct spe_stats));

    for (int i = 0; i < config.num_cpu; i++)
    {
        configure_cpu_session(&sessions[i], &pmus[i]);
    }

    // set up btree
    vm_spe_tr = btree_new(sizeof(struct vm_spe_btree_entry), 0, vm_spe_btree_compare, NULL);
    btree_clear(vm_spe_tr);

    // initialize mapping table and read /proc/map to get all currently running processes
    // this is needed as currently running processes do not generate MMAP2 records
    mapping_table = init_pid_maps();
    get_initial_mappings(mapping_table);

    uint64_t iters = config.timeout / ((double)config.period / 1000);
    // main event loop
    for (int itr = 0; itr < iters; itr++)
    {
        usleep(1000 * config.period);

        for (int i = 0; i < config.num_cpu; i++)
        {
            traverse_buffers(&pmus[i], &sessions[i]);
        }
    }

    disable_all_pmus(pmus, &config);

    commit_to_file();
    exit(EXIT_SUCCESS);
}
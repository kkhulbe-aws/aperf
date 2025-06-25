#include "config.h"
#include "auxtrace.h"
#include "heap.h"
#include "vm_spe_btree.h"
#include "btree.h"
#include "mmap_table.h"
#include <stdatomic.h>

// global data structures independent of sessions
struct btree *vm_spe_tr;
char *global_filenames[MAX_FILENAMES];
size_t global_filename_count = 0;
struct pid_maps_table *mapping_table;

extern int build_report();

#ifndef HOTLINE_DIR
#define HOTLINE_DIR "/home/ubuntu/hotline"
#endif

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

/**
 * On every event loop:
 * 1. Iterate through record buffer
 * 2. If the event is PERF_RECORD_MMAP2, add event to min heap
 * 3. If the event is PERF_RECORD_AUX
 *      a. Add entries to min heap and convert time stamp
 * 4. If the event is PERF_RECORD_CONTEXT_SWITCH_CPU_WIDE
 *      b. Add entry to min heap
 * 5. Drain the min heap
 *      a. If the heap entry is a hotline entry --> update aggregate statistics for pids
 *      b. If the heap entry is an MMAP entry (add or delete) --> update MMAPings
 *      c. If the heap entry is a SWITCH --> udpate the current session
 *
 * The min heap is required because the context switch events and aux events are not sequential
 * therefore, we may have an aux event at a timestamp later than a context switch show up earlier.
 * Perf approaches these events the same way

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
 * | current |----> Ordered  <----+ B-Tree    |
 * |  PID    |    | Samples  |    |           |
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
 * On some workloads (particularly those that just hammer the memory modules), CPU usage increases due to context switching and large amounts
 * of events being generated. In the worst case, it increases to 10-11%. To mitigate this, the --throttle flag allows the tool to throttle records.
 * The tool throttles the record buffer at 64000 records / second. This is divided by the number of CPUs to ensure that this throttle amount is met.
 */

const char *get_hotline_dir()
{
    const char *env_dir = getenv("HOTLINE_DIR");
    return env_dir ? env_dir : HOTLINE_DIR;
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
    fflush(stdout); // Important to flush the output
}

void commit_to_file()
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "hotlines_loads.data");
    FILE *load_fp = fopen(path, "w");

    memset(path, 0, sizeof(char) * PATH_MAX);
    snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "hotlines_branches.data");
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
    printf("Configuration:\n");
    printf("\tPeriod: %d ms\n", config.period);
    printf("\tSPE Period: %d cycles\n", config.spe_period);
    printf("\tNumber of CPUs: %d\n", config.num_cpu);
    printf("\tLoad Filter: %d cycles\n", config.load_filter);
    printf("\tTimeout: %d s\n", config.timeout);
    printf("\tShould Throttle: %d s\n", config.throttle);
    printf("\tDirectory: %s\n", get_hotline_dir());

    configure_all_pmus(pmus, &config);
    // printf("PMUs configured.\n");

    reset_all_pmus(pmus, &config);
    // printf("PMUs reset.\n");

    struct spe_stats stats;
    memset(&stats, 0, sizeof(struct spe_stats));

    for (int i = 0; i < config.num_cpu; i++)
    {
        configure_cpu_session(&sessions[i], &pmus[i]);
    }

    // printf("CPU sessions have been set up.\n");

    // set up btree
    vm_spe_tr = btree_new(sizeof(struct vm_spe_btree_entry), 0, vm_spe_btree_compare, NULL);
    btree_clear(vm_spe_tr);

    // printf("B-Tree setup.\n");

    enable_all_pmus(pmus, &config);

    // printf("Profiling has begun.\n");

    // initialize mapping table and read /proc/map to get all currently running processes
    // this is needed as currently running processes do not generate MMAP2 records
    mapping_table = init_pid_maps();
    get_initial_mappings(mapping_table);

    uint64_t iters = config.timeout / ((double)config.period / 1000);
    // main event loop
    for (int itr = 0; itr < iters; itr++)
    {
        // Ensure sleep is completed before proceeding
        atomic_thread_fence(memory_order_seq_cst);
        usleep(1000 * config.period);
        atomic_thread_fence(memory_order_seq_cst);

        volatile uint64_t heap_entries = 0;

        // fence before PMU operations
        __sync_synchronize();

        for (int i = 0; i < config.num_cpu; i++)
        {
            __asm__ __volatile__("" ::: "memory");
            // traverse_buffers(&pmus[i], &sessions[i]);
            process_record_buffer(&pmus[i], &stats, &sessions[i], config.num_cpu, config.period, config.throttle);
            process_record_aux(&pmus[i], &sessions[i], config.num_cpu, config.period, config.throttle);
            heap_entries += drain_heap(&sessions[i]);

            // force completion of PMU operations
            __sync_synchronize();
            atomic_thread_fence(memory_order_seq_cst);

            // ARM-specific memory barrier
            __asm__ __volatile__("dmb ish" ::: "memory");
        }

        __sync_synchronize();
        atomic_thread_fence(memory_order_seq_cst);
    }

    // ensure all operations complete before disabling PMUs
    __sync_synchronize();
    atomic_thread_fence(memory_order_seq_cst);
    print_progress_bar(100);
    disable_all_pmus(pmus, &config);


    // printf("Disabled.\n");

    printf("\nProfiling complete. Dumping data.\n");
    commit_to_file();
    printf("\nData generated. Building report. \n\n");
    build_report();
    printf("\nEverything written to {hotlines_branches.report} and {hotlines_loads.report}. Have a great day :)\n\n");
    exit(EXIT_SUCCESS);
}
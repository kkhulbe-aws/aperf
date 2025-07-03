#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auxtrace.h"
#include "btree.h"
#include "config.h"
#include "mmap_table.h"
#include "vm_spe_btree.h"
#include "rs_interface.h"

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
 * 1. Loop through the AUX buffer, starting from where we left off on the
 * previous loop
 * 2. Upgrade the timestamp of the session by iterating through the record
 * buffer up to the timestamp right before the current AUX entry a. If it is
 * PERF_RECORD_SWITCH_CPU_WIDE: if it is a switch out, update the current
 * session pid b. If it is PERF_RECORD_MMAP2: update the mmap datastructures
 * with the new mappings c. If it is PERF_RECORD_EXIT: clean out the mmap
 * mappings for the corresponding pid
 *
 * The tool is implemented with this two pointer mechanism rather than a
 * min-heap because we observed the CPU utilization overhead of the minheap is
 * non-trivial, and can reach upwards of 9-11%, on worst-case workloads. This
 * mechanism has an observed worst-case of 2% and average of 1%, which motivates
 * enabling it by default on APerf.
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
 * +---------+    +-----------+    +-----------+
 * | Session |    |           |    | hotline   |
 * | current |----> Main loop <----+ B-Tree    |
 * |  PID    |    |           |    |           |
 * +---------+    +-----------+    +-----------+
 *                     ^                |
 *                     |                |
 *                     |                v
 *                +---------+           |
 *                |         |           |
 *                |MMAPings |<----------+
 *                |         |
 *                +---------+
 *
 * The B-Tree is what aggregates all the statistics for the user. In order to do
 * so, we need to know what the current pid is (hence the
 * PERF_RECORD_SWITCH_CPU_WIDE records), and a mapping structure for the virtual
 * address offsets. To ensure proper time ordering, everything is inserted into
 * the heap, pulled out, and processed in the corresponding data structures.
 *
 * The tool maintains a legacy implementation using the min-heap, and can be
 * swapped out for the two pointer method.
 */

const char *get_hotline_dir() {
  const char *env_dir = getenv("HOTLINE_DIR");
  return env_dir ? env_dir : "";
}

const char *get_hotline_report_dir() {
  const char *env_dir = getenv("HOTLINE_REPORT_DIR");
  return env_dir ? env_dir : "";
}

void signal_handler(int signum) {
  commit_to_file();
  exit(signum);
}

void commit_to_file(void) {
    char path[PATH_MAX];
    FILE *load_fp = NULL;
    FILE *branch_fp = NULL;
    struct btree_iter *iter = NULL;
    bool success = false;

    // open load file
    if (snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "spe_hotline_loads.bin") < 0) {
        rs_wrapper_error("Error creating load file path\n");
        return;
    }
    load_fp = fopen(path, "w");

    // open branch file 
    if (snprintf(path, sizeof(path), "%s/%s", get_hotline_dir(), "spe_hotline_branches.bin") < 0) {
        rs_wrapper_error("Error creating branch file path\n");
        goto cleanup;
    }
    branch_fp = fopen(path, "w");

    // Verify file handles
    if (!load_fp || !branch_fp) {
        rs_wrapper_error("Error opening output files\n");
        goto cleanup;
    }

    // write headers
    if (fprintf(load_fp, "filename,offset,retired_insts,total_latency,issue_latency,"
                "translation_latency,"
                "l1_bin1,l1_bin2,l1_bin3,l1_bin4,"
                "l2_bin1,l2_bin2,l2_bin3,l2_bin4,"
                "l3_bin1,l3_bin2,l3_bin3,l3_bin4,"
                "dram_bin1,dram_bin2,dram_bin3,dram_bin4,saturated\n") < 0) {
        rs_wrapper_error("Error writing load header\n");
        goto cleanup;
    }

    if (fprintf(branch_fp, "filename,offset,retired_insts,not_taken_branches,"
                "mispredicted,total_latency,issue_latency,saturated,branch_type\n") < 0) {
        rs_wrapper_error("Error writing branch header\n");
        goto cleanup;
    }

    // initialize btree iterator
    iter = btree_iter_new(vm_spe_tr);
    if (!iter) {
        rs_wrapper_error("Failed to create btree iterator\n");
        goto cleanup;
    }

    // process entries
    for (bool ok = btree_iter_first(iter); ok; ok = btree_iter_next(iter)) {
        struct vm_spe_btree_entry *entry = 
            (struct vm_spe_btree_entry *)btree_iter_item(iter);
        
        if (!entry) continue;

        int write_result;
        if (entry->type == AUX_RECORD_LOAD) {
            write_result = fprintf(load_fp,
                "%s,0x%lx,%lu,%lu,%lu,%lu,"
                "%lu,%lu,%lu,%lu,"       // l1 bins
                "%lu,%lu,%lu,%lu,"       // l2 bins
                "%lu,%lu,%lu,%lu,"       // l3 bins
                "%lu,%lu,%lu,%lu,%lu\n", // dram bins
                global_filenames[entry->file_id], entry->offset,
                entry->retired_insts, entry->total_latency, entry->issue_latency,
                entry->load_entry.x_latency, entry->load_entry.l1.bin_1,
                entry->load_entry.l1.bin_2, entry->load_entry.l1.bin_3,
                entry->load_entry.l1.bin_4, entry->load_entry.l2.bin_1,
                entry->load_entry.l2.bin_2, entry->load_entry.l2.bin_3,
                entry->load_entry.l2.bin_4, entry->load_entry.l3.bin_1,
                entry->load_entry.l3.bin_2, entry->load_entry.l3.bin_3,
                entry->load_entry.l3.bin_4, entry->load_entry.dram.bin_1,
                entry->load_entry.dram.bin_2, entry->load_entry.dram.bin_3,
                entry->load_entry.dram.bin_4, entry->saturated_packets);
        } else if (entry->type == AUX_RECORD_BRANCH) {
            write_result = fprintf(branch_fp, 
                "%s,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%x\n",
                global_filenames[entry->file_id], entry->offset,
                entry->retired_insts, entry->branch_entry.not_taken_branches,
                entry->branch_entry.mispredicted, entry->total_latency,
                entry->issue_latency, entry->saturated_packets,
                entry->branch_entry.branch_type);
        } else {
            continue;
        }

        if (write_result < 0) {
            rs_wrapper_error("Error writing entry to file\n");
            goto cleanup;
        }
    }

    success = true;

cleanup:
    if (load_fp) fclose(load_fp);
    if (branch_fp) fclose(branch_fp);
    if (iter) btree_iter_free(iter);
    if (vm_spe_tr) btree_free(vm_spe_tr);
    free_pid_maps_table(mapping_table);

    if (!success) {
        fprintf(stderr, "commit_to_file failed\n");
    }
}

int hotline_main(int argc, char *argv[]) {
    struct arg_config config = {0};
    struct arm_spe_pmu *pmus = NULL;
    struct cpu_session *sessions = NULL;
    
    // parse arguments
    parse_arguments(argc, argv, &config);
    configure_cache_bins(&config);
    
    // allocate PMU and session arrays
    pmus = calloc(config.num_cpu, sizeof(struct arm_spe_pmu));
    if (!pmus) {
        rs_wrapper_error("Failed to allocate PMU array");
        return EXIT_FAILURE;
    }
    
    sessions = calloc(config.num_cpu, sizeof(struct cpu_session));
    if (!sessions) {
        rs_wrapper_error("Failed to allocate session array");
        free(pmus);
        return EXIT_FAILURE;
    }
    
    // configure signal handling
    struct sigaction sa = {
        .sa_handler = signal_handler,
        .sa_flags = 0
    };
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        rs_wrapper_error("Cannot handle SIGTERM");
        free(pmus);
        free(sessions);
        return EXIT_FAILURE;
    }
    
    // initialize and configure PMUs
    configure_all_pmus(pmus, &config);
    reset_all_pmus(pmus, &config);
    enable_all_pmus(pmus, &config);
    
    // configure CPU sessions
    for (int i = 0; i < config.num_cpu; i++) {
        configure_cpu_session(&sessions[i], &pmus[i]);
    }
    
    // initialize btree
    vm_spe_tr = btree_new(sizeof(struct vm_spe_btree_entry), 0,
                          vm_spe_btree_compare, NULL);
    btree_clear(vm_spe_tr);
    
    // initialize mapping table and read /proc/map to get all currently running
    // processes this is needed as currently running processes do not generate
    // MMAP2 records
    mapping_table = init_pid_maps();
    get_initial_mappings(mapping_table);
    
    // main event loop
    uint64_t iters = config.timeout / ((double)config.period / 1000);
    for (int itr = 0; itr < iters; itr++) {
        sleep(config.period);
        
        for (int i = 0; i < config.num_cpu; i++) {
            traverse_buffers(&pmus[i], &sessions[i], &config);
        }
    }
    
    // cleanup and exit
    disable_all_pmus(pmus, &config);
    free(pmus);
    free(sessions);
    
    commit_to_file();
    return EXIT_SUCCESS;
}
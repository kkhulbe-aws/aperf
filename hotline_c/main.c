#include "log.h"
#include "sys.h"
#include "config.h"
#include "hotline.h"
#include "fname_map.h"

int main(int argc, char *argv[]) {
    init_sys_info();
    printf("%lx\n", CPU_SYSTEM_CONFIG.cpu_part);
    printf("%lu\n", CPU_SYSTEM_CONFIG.frequency);
    printf("%lu\n", CPU_SYSTEM_CONFIG.page_size);

    printf("\t%lu\n", CPU_SYSTEM_CONFIG.latency_limits.l1_max_cycles);
    printf("\t%lu\n", CPU_SYSTEM_CONFIG.latency_limits.l2_max_cycles);
    printf("\t%lu\n", CPU_SYSTEM_CONFIG.latency_limits.l3_max_cycles);

    parse_arguments(argc, argv);

    printf("%u\n", PROFILE_CONFIGURATION.wakeup_period);
    printf("%u\n", PROFILE_CONFIGURATION.spe_sample_frequency);
    printf("%u\n", PROFILE_CONFIGURATION.timeout);

    cpu_session_t session = {0};
    session.cpu = 0;

    init_sessions();
    init_fname_map();

    enable_perf_profiling();
    printf("enabled profiling.\n");
    while (1) {
        sleep(1);
        for (int i = 0; i < 64; i++)
            process_aux_buffer(&sessions[i]);
        printf("aggregated.\n");
        printf("MMAP: %lu\n", btree_count(FNAME_MAP));
    }
    return 0;
}
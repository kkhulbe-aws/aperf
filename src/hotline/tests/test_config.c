#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

void test_init() {
    cpu_system_config.page_size = 4096;
}

void test_parse_arguments_defaults() {        
    // Reset getopt's global state
    optind = 1;  // Reset to 1 before parsing arguments
    
    char *argv[] = {"test_program"};
    int argc = 1;
    
    parse_arguments(argc, argv);
    
    assert(profile_configuration.wakeup_period == PROFILE_DEFAULT_WAKEUP_PERIOD);
    assert(profile_configuration.spe_sample_frequency == PROFILE_DEFAULT_SPE_SAMPLE_FREQ);
    assert(profile_configuration.timeout == PROFILE_DEFAULT_TIMEOUT);
    assert(profile_configuration.num_to_report == PROFILE_DEFAULT_NUM_REPORT);
    assert(strcmp(profile_configuration.data_dir, "./data") == 0);
    assert(strcmp(profile_configuration.report_dir, "./report") == 0);
}

void test_parse_arguments_custom() {        
    // Reset getopt's global state
    optind = 1;  // Reset to 1 before parsing arguments
    
    char *argv[] = {"test_program", "--wakeup_period", "5", "--spe_sample_frequency", "2000", 
                    "--timeout", "30", "--data_dir", "/tmp/data", "--report_dir", "/tmp/report"};
    int argc = 11;
    
    parse_arguments(argc, argv);
    
    assert(profile_configuration.wakeup_period == 5);
    assert(profile_configuration.spe_sample_frequency == 2000);
    assert(profile_configuration.timeout == 30);
    assert(strcmp(profile_configuration.data_dir, "/tmp/data") == 0);
    assert(strcmp(profile_configuration.report_dir, "/tmp/report") == 0);
}

void test_parse_arguments_short_options() {    
    // Reset getopt's global state
    optind = 1;  // Reset to 1 before parsing arguments
    
    char *argv[] = {"test_program", "-p", "3", "-s", "1500", "-t", "20", 
                    "-d", "/custom/data", "-r", "/custom/report"};
    int argc = 11;
    
    parse_arguments(argc, argv);
    
    assert(profile_configuration.wakeup_period == 3);
    assert(profile_configuration.spe_sample_frequency == 1500);
    assert(profile_configuration.timeout == 20);
    assert(strcmp(profile_configuration.data_dir, "/custom/data") == 0);
    assert(strcmp(profile_configuration.report_dir, "/custom/report") == 0);
}

void test_get_perf_buffer_sizes() {    
    // Set up configuration
    profile_configuration.wakeup_period = 2;
    profile_configuration.spe_sample_frequency = 1000;
    
    perf_buffer_size_t buffer_sizes;
    get_perf_buffer_sizes(&buffer_sizes);
    
    // Verify calculations
    uint64_t expected_record_buf = 4096 * 2 * 4096; // num_pages * wakeup_period * page_size
    uint64_t expected_aux_buf_raw = 1000 * 2 * sizeof(aux_record_raw_t) * 8;
    
    assert(buffer_sizes.perf_record_buf_sz == expected_record_buf);
    assert(buffer_sizes.perf_aux_off == expected_record_buf + 4096);
    // aux_buf_sz should be power of 2 >= expected_aux_buf_raw
    assert(buffer_sizes.perf_aux_buf_sz >= expected_aux_buf_raw);
    assert((buffer_sizes.perf_aux_buf_sz & (buffer_sizes.perf_aux_buf_sz - 1)) == 0); // power of 2 check    
}

void test_get_perf_buffer_sizes_different_config() {
    profile_configuration.wakeup_period = 1;
    profile_configuration.spe_sample_frequency = 500;
    
    perf_buffer_size_t buffer_sizes;
    get_perf_buffer_sizes(&buffer_sizes);
    
    uint64_t expected_record_buf = 4096 * 1 * 4096;
    assert(buffer_sizes.perf_record_buf_sz == expected_record_buf);
    assert(buffer_sizes.perf_aux_off == expected_record_buf + 4096);
    assert((buffer_sizes.perf_aux_buf_sz & (buffer_sizes.perf_aux_buf_sz - 1)) == 0);
}

void test_config() {
    test_init();
    
    test_parse_arguments_defaults();
    test_parse_arguments_custom();
    test_parse_arguments_short_options();
    test_get_perf_buffer_sizes();
    test_get_perf_buffer_sizes_different_config();
}
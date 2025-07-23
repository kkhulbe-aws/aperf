extern crate ctor;

use crate::data::{CollectData, CollectorParams, ProcessedData};
use crate::utils::DataMetrics;
use crate::visualizer::{GetData, ReportParams};
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(feature = "hotline")]
use {
    crate::{
        data::{Data, DataType},
        visualizer::DataVisualizer,
        PERFORMANCE_DATA, VISUALIZATION_DATA,
    },
    ctor::ctor,
    libc::{_exit, fork, geteuid, killpg, setpgid, waitpid, SIGTERM},
    log::{info, warn},
    std::{
        env,
        ffi::CString,
        fs,
        os::raw::{c_char, c_int},
        panic,
    },
};

#[cfg(feature = "hotline")]
extern "C" {
    fn hotline(argc: c_int, argv: *const *const i8) -> c_int;
    fn deserialize_maps(argc: c_int, argv: *const *const i8) -> c_int;
}

pub static HOTLINE_FILE_NAME: &str = "hotline_profile";

#[cfg(feature = "hotline")]
pub fn check_preconditions() -> Result<bool> {
    let mut all_conditions_met = true;

    // Check root privileges
    let euid = unsafe { geteuid() } == 0;
    if !euid {
        warn!("Not running with root privileges. Please run with sudo.");
        all_conditions_met = false;
    }

    // Check KPTI status
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let kpti_off = cmdline.contains("kpti=off");
    if !kpti_off {
        warn!("KPTI is not disabled. Add 'kpti=off' to GRUB_CMDLINE_LINUX_DEFAULT and reboot.");
        all_conditions_met = false;
    }

    // Check kptr_restrict
    let kptr_value = fs::read_to_string("/proc/sys/kernel/kptr_restrict")?
        .trim()
        .parse::<i32>()
        .unwrap_or(-1);
    if kptr_value != 0 {
        warn!(
            "kptr_restrict is not set to 0. Run: echo 0 | sudo tee /proc/sys/kernel/kptr_restrict"
        );
        all_conditions_met = false;
    }

    // Check perf_event_paranoid
    let paranoid_value = fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")?
        .trim()
        .parse::<i32>()
        .unwrap_or(4);
    if paranoid_value != -1 {
        warn!("perf_event_paranoid is not set to -1. Run: echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid");
        all_conditions_met = false;
    }

    // Check /proc/kallsyms readable
    let kallsyms_readable = match fs::metadata("/proc/kallsyms") {
        Ok(metadata) => metadata.permissions().readonly(),
        Err(_) => false,
    };
    if !kallsyms_readable {
        warn!("/proc/kallsyms is not readable. Run: sudo chmod +r /proc/kallsyms");
        all_conditions_met = false;
    }

    if !all_conditions_met {
        Ok(false)
    } else {
        info!("All preconditions are met.");
        Ok(true)
    }
}

#[cfg(feature = "hotline")]
pub mod hotline_reports {
    use super::ReportParams;
    use std::error::Error;
    use std::fs::File;
    use std::io::{Read, Write};

    struct ReportConfig<'a> {
        title: &'a str,
        filename: &'a str,
    }

    const REPORT_CONFIGS: [ReportConfig; 5] = [
        ReportConfig {
            title: "Completion Node View",
            filename: "hotline_lat_map_completion_report.csv",
        },
        ReportConfig {
            title: "Execution Latency View",
            filename: "hotline_lat_map_exec_report.csv",
        },
        ReportConfig {
            title: "Issue Latency View",
            filename: "hotline_lat_map_issue_report.csv",
        },
        ReportConfig {
            title: "Translation Latency View",
            filename: "hotline_lat_map_translation_report.csv",
        },
        ReportConfig {
            title: "Branch View",
            filename: "hotline_bmiss_map.csv",
        },
    ];

    pub fn generate_reports(params: &ReportParams) -> Result<(), Box<dyn Error>> {
        let report_paths = get_report_paths(params);
        generate_html_tables(params, &report_paths)?;
        Ok(())
    }

    fn get_report_paths(params: &ReportParams) -> Vec<(String, String)> {
        REPORT_CONFIGS
            .iter()
            .map(|config| {
                (
                    config.title.to_string(),
                    format!("{}/data/{}", params.report_dir.display(), config.filename),
                )
            })
            .collect()
    }

    fn generate_html_tables(
        params: &ReportParams,
        report_paths: &[(String, String)],
    ) -> Result<(), Box<dyn Error>> {
        for (title, csv_path) in report_paths {
            match generate_single_table(params, title, csv_path) {
                Ok(_) => (),
                Err(e) => eprintln!("Warning: Failed to generate table for {}: {}", title, e),
            }
        }
        Ok(())
    }

    fn generate_single_table(
        params: &ReportParams,
        title: &str,
        csv_path: &str,
    ) -> Result<(), Box<dyn Error>> {
        let html_content = read_and_convert_csv(csv_path)?;
        let filename = format!("{}.html", title.to_lowercase().replace(" ", "_"));
        write_html_file(params, &filename, &generate_html(title, &html_content))
    }

    fn read_and_convert_csv(csv_path: &str) -> Result<String, Box<dyn Error>> {
        let mut content = String::new();
        File::open(csv_path)?.read_to_string(&mut content)?;
        Ok(csv_to_html::convert(&content, &b',', &true))
    }

    fn generate_html(title: &str, table_content: &str) -> String {
        let modified_content = add_column_classes(table_content);
        format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{}</title>
                <link rel="stylesheet" href="index.css">
            </head>
            <body>
                <div id="{}-table">
                    <h2>{}</h2>
                    <div class="table-container">
                        {}
                    </div>
                </div>
            </body>
            </html>"#,
            title,
            title.to_lowercase().replace(" ", "-"),
            title,
            modified_content
        )
    }

    fn add_column_classes(html: &str) -> String {
        let mut lines: Vec<String> = html.lines().map(String::from).collect();
        if let Some(header) = lines.first_mut() {
            *header = header.replace(
                "<th>Assembly</th>",
                "<th class=\"assembly-column\">Assembly</th>",
            );
            *header = header.replace("<th>Source</th>", "<th class=\"source-column\">Source</th>");
        }
        for line in lines.iter_mut().skip(1) {
            *line = line.replace("<td>", "<td class=\"cell\">");
        }
        lines.join("\n")
    }

    fn write_html_file(
        params: &ReportParams,
        filename: &str,
        content: &str,
    ) -> Result<(), Box<dyn Error>> {
        let path = params.report_dir.join("data/js").join(filename);
        File::create(path)?.write_all(content.as_bytes())?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HotlineRaw {
    pid: i32,
    launched: bool,
}

impl HotlineRaw {
    fn new() -> Self {
        HotlineRaw {
            pid: 0,
            launched: false,
        }
    }
}

impl CollectData for HotlineRaw {
    #[cfg(feature = "hotline")]
    fn prepare_data_collector(&mut self, params: &CollectorParams) -> Result<()> {
        match check_preconditions() {
            Ok(false) => {
                warn!("Skipping Hotline.");
                self.launched = false;
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to check preconditions: {}", e);
                self.launched = false;
                return Ok(());
            }
            _ => {}
        }

        let args = vec![
            CString::new("hotline").unwrap(),
            CString::new("--wakeup_period").unwrap(),
            CString::new(params.interval.to_string()).unwrap(),
            CString::new("--hotline_frequency").unwrap(),
            CString::new(params.hotline_frequency.to_string()).unwrap(),
            CString::new("--timeout").unwrap(),
            CString::new(params.collection_time.to_string()).unwrap(),
            CString::new("--data_dir").unwrap(),
            CString::new(params.data_dir.to_str().unwrap()).unwrap(),
        ];

        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();

        unsafe {
            match fork() {
                -1 => {
                    eprintln!("Fork failed");
                    Ok(()) // Return Ok even if fork fails
                }
                0 => {
                    // Child process
                    if setpgid(0, 0) == -1 {
                        eprintln!("Failed to set process group");
                        _exit(1);
                    }

                    // Setup signal handlers
                    let mut sigset = std::mem::MaybeUninit::uninit();
                    libc::sigemptyset(sigset.as_mut_ptr());
                    libc::sigaddset(sigset.as_mut_ptr(), SIGTERM);
                    libc::sigprocmask(libc::SIG_UNBLOCK, sigset.as_ptr(), std::ptr::null_mut());

                    let result = hotline(args.len() as c_int, argv.as_ptr() as *const *const i8);
                    _exit(result);
                }
                pid => {
                    // Parent process
                    self.pid = pid;
                    self.launched = true;
                    Ok(())
                }
            }
        }
    }

    #[cfg(not(feature = "hotline"))]
    fn prepare_data_collector(&mut self, _params: &CollectorParams) -> Result<()> {
        Ok(())
    }

    fn collect_data(&mut self, _params: &CollectorParams) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "hotline")]
    fn finish_data_collection(&mut self, _: &CollectorParams) -> Result<()> {
        if !self.launched {
            return Ok(());
        }

        unsafe {
            // Send SIGTERM to the process group
            if killpg(self.pid, SIGTERM) == -1 {
                let err = std::io::Error::last_os_error();
                eprintln!("Warning: Failed to kill process group: {}", err);
            }

            // Wait for the child process to finish
            let mut status: c_int = 0;
            match waitpid(self.pid, &mut status, 0) {
                -1 => {
                    let err = std::io::Error::last_os_error();
                    eprintln!("Warning: Failed to wait for child process: {}", err);
                }
                _ => {
                    if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
                        return Err(anyhow::anyhow!("Child process terminated abnormally"));
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "hotline"))]
    fn finish_data_collection(&mut self, _: &CollectorParams) -> Result<()> {
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hotline {}

impl Hotline {
    fn new() -> Self {
        Hotline {}
    }
}

impl GetData for Hotline {
    #[cfg(feature = "hotline")]
    fn custom_raw_data_parser(&mut self, params: ReportParams) -> Result<Vec<ProcessedData>> {
        let args = vec![
            CString::new("hotline").unwrap(),
            CString::new("--num_to_report").unwrap(),
            CString::new(params.num_to_report.to_string()).unwrap(),
            CString::new("--data_dir").unwrap(),
            CString::new(params.data_dir.to_str().unwrap()).unwrap(),
            CString::new("--report_dir").unwrap(),
            CString::new(format!("{}/data", params.report_dir.to_str().unwrap())).unwrap(),
        ];

        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();

        // Run deserialize_maps in a child process
        unsafe {
            match fork() {
                -1 => {
                    eprintln!("Fork failed");
                }
                0 => {
                    // Child process
                    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                        deserialize_maps(args.len() as c_int, argv.as_ptr() as *mut *const i8);
                    }));
                    match result {
                        Ok(_) => _exit(0),
                        Err(_) => _exit(1),
                    }
                }
                pid => {
                    // Parent process
                    let mut status: c_int = 0;
                    if waitpid(pid, &mut status, 0) == -1 {
                        eprintln!("Failed to wait for deserialize_maps process");
                    }
                }
            }
        }

        match hotline_reports::generate_reports(&params) {
            Ok(_) => (),
            Err(e) => eprintln!("Warning: Failed to generate HTML tables: {}", e),
        }

        Ok(vec![])
    }

    #[cfg(not(feature = "hotline"))]
    fn custom_raw_data_parser(&mut self, params: ReportParams) -> Result<Vec<ProcessedData>> {
        Ok(vec![])
    }

    fn get_calls(&mut self) -> Result<Vec<String>> {
        Ok(vec![])
    }

    fn get_data(
        &mut self,
        _: Vec<ProcessedData>,
        _query: String,
        _metrics: &mut DataMetrics,
    ) -> Result<String> {
        Ok("".to_string())
    }
}

#[ctor]
#[cfg(feature = "hotline")]
fn init_hotline_profile() {
    let hotline_raw = HotlineRaw::new();
    let file_name = HOTLINE_FILE_NAME.to_string();
    let dt = DataType::new(
        Data::HotlineRaw(hotline_raw.clone()),
        file_name.clone(),
        false,
    );
    let hotline_profile = Hotline::new();
    let js_file_name = file_name.clone() + ".js";
    let mut dv = DataVisualizer::new(
        ProcessedData::Hotline(hotline_profile.clone()),
        file_name.clone(),
        js_file_name,
        include_str!(concat!(env!("JS_DIR"), "/hotline.js")).to_string(),
        file_name.clone(),
    );
    dv.has_custom_raw_data_parser();

    PERFORMANCE_DATA
        .lock()
        .unwrap()
        .add_datatype(file_name.clone(), dt);

    VISUALIZATION_DATA
        .lock()
        .unwrap()
        .add_visualizer(file_name.clone(), dv);
}

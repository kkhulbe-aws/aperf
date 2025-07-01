extern crate ctor;

use crate::data::{CollectData, CollectorParams, Data, DataType, ProcessedData};
use crate::utils::DataMetrics;
use crate::visualizer::{DataVisualizer, GetData, ReportParams};
use crate::{PERFORMANCE_DATA, VISUALIZATION_DATA};
use anyhow::Result;
use csv_to_html;
use ctor::ctor;
use libc::{_exit, c_int, fork};
use log::info;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::raw::c_char;

#[cfg(feature = "spe")]
unsafe extern "C" {
    fn hotline_main(argc: c_int, argv: *const *const i8) -> c_int;
    fn build_report();
}

pub static SPE_PROFILE_FILE_NAME: &str = "spe_profile";

fn generate_html_tables(
    params: &ReportParams,
    completion_csv: &str,
    exec_latency_csv: &str,
    issue_latency_csv: &str,
    translation_latency_csv: &str,
    branch_csv: &str,
) -> Result<(), Box<dyn Error>> {
    // Read and convert CSV files to HTML
    let completion_html = read_and_convert_csv(completion_csv)?;
    let exec_latency_html = read_and_convert_csv(exec_latency_csv)?;
    let issue_latency_html = read_and_convert_csv(issue_latency_csv)?;
    let translation_latency_html = read_and_convert_csv(translation_latency_csv)?;
    let branch_html = read_and_convert_csv(branch_csv)?;

    // CSS for table styling
    let table_style = r#"
        <style>
            table {
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 1em;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
                white-space: nowrap; /* Prevent text wrapping */
                overflow: hidden;
                text-overflow: ellipsis;
                max-width: 300px; /* Adjust this value as needed */
            }
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
            tr:nth-child(even) {
                background-color: #f9f9f9;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .table-container {
                width: 100%;
                overflow-x: auto; /* Add horizontal scroll for wide tables */
            }
            .toggle-button {
                margin: 10px;
                padding: 5px 10px;
                cursor: pointer;
            }
            /* Specific column widths */
            .assembly-column, .source-column {
                min-width: 300px;
                max-width: 500px;
            }
        </style>
    "#;

    let completion_table_html =
        generate_html("Completion Node View", table_style, &completion_html);
    let exec_latency_table_html =
        generate_html("Execution Latency View", table_style, &exec_latency_html);
    let issue_latency_table_html =
        generate_html("Issue Latency View", table_style, &issue_latency_html);
    let translation_latency_table_html = generate_html(
        "Translation Latency View",
        table_style,
        &translation_latency_html,
    );
    let branch_table_html = generate_html("Branch View", table_style, &branch_html);

    // Write the HTML files
    write_html_file(params, "completion_node_view.html", &completion_table_html)?;
    write_html_file(params, "exec_latency_view.html", &exec_latency_table_html)?;
    write_html_file(params, "issue_latency_view.html", &issue_latency_table_html)?;
    write_html_file(
        params,
        "translation_latency_view.html",
        &translation_latency_table_html,
    )?;
    write_html_file(params, "branch_view.html", &branch_table_html)?;

    Ok(())
}

fn read_and_convert_csv(csv_path: &str) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(csv_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(csv_to_html::convert(&content, &b',', &true))
}

fn generate_html(title: &str, table_style: &str, table_content: &str) -> String {
    // Function to add class to specific columns
    fn add_column_classes(html: &str) -> String {
        let mut lines: Vec<String> = html.lines().map(String::from).collect();
        if let Some(header) = lines.first_mut() {
            *header = header.replace("<th>Assembly</th>", "<th class=\"assembly-column\">Assembly</th>");
            *header = header.replace("<th>Source</th>", "<th class=\"source-column\">Source</th>");
        }
        for line in lines.iter_mut().skip(1) {
            *line = line.replace("<td>", "<td class=\"cell\">");
        }
        lines.join("\n")
    }

    format!(
        r#"<div id="{}-table">
            <h2>{}</h2>
            {}
            <div class="table-container">
                {}
            </div>
        </div>"#,
        title.to_lowercase().replace(" ", "-"),
        title,
        table_style,
        add_column_classes(table_content)
    )
}


fn write_html_file(
    params: &ReportParams,
    filename: &str,
    content: &str,
) -> Result<(), Box<dyn Error>> {
    let path = params.report_dir.join("data/js").join(filename);
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SPEProfileRaw {
    pid: i32,
}

impl SPEProfileRaw {
    fn new() -> Self {
        SPEProfileRaw { pid: 0 }
    }
}

impl CollectData for SPEProfileRaw {
    fn prepare_data_collector(&mut self, params: &CollectorParams) -> Result<()> {
        #[cfg(feature = "spe")]
        {
            let args = vec![
                CString::new("hotline").unwrap(),
                CString::new("--num_cpu").unwrap(),
                CString::new(params.num_cpu.to_string()).unwrap(),
                CString::new("--period").unwrap(),
                CString::new(params.spe_wakeup_period.to_string()).unwrap(),
                CString::new("--spe_period").unwrap(),
                CString::new(params.spe_period.to_string()).unwrap(),
                CString::new("--timeout").unwrap(),
                CString::new((params.collection_time - 1).to_string()).unwrap(),
                CString::new("--throttle").unwrap(),
                CString::new(0.to_string()).unwrap(),
            ];

            let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();

            unsafe {
                env::set_var("HOTLINE_DIR", params.data_dir.clone());
            }

            unsafe {
                // fork the process
                match fork() {
                    -1 => {
                        // fork failed
                        return Err(anyhow::anyhow!("Fork failed"));
                    }
                    0 => {
                        // child process
                        if libc::setpgid(0, 0) == -1 {
                            eprintln!("Failed to set process group");
                            _exit(1);
                        }
                        let result =
                            hotline_main(args.len() as c_int, argv.as_ptr() as *const *const i8);
                        _exit(result);
                    }
                    pid => {
                        // parent process
                        self.pid = pid;
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_data(&mut self, _params: &CollectorParams) -> Result<()> {
        Ok(())
    }

    fn finish_data_collection(&mut self, _: &CollectorParams) -> Result<()> {
        #[cfg(feature = "spe")]
        {
            unsafe {
                // send SIGTERM to the process group
                if libc::killpg(self.pid, libc::SIGTERM) == -1 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow::anyhow!("Failed to kill process group: {}", err));
                }

                // wait for the child process to finish
                let mut status: c_int = 0;
                if libc::waitpid(self.pid, &mut status, 0) == -1 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow::anyhow!("Failed to wait for child process: {}", err));
                }
            }
            return Ok(());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SPEProfile {}

impl SPEProfile {
    fn new() -> Self {
        SPEProfile {}
    }
}

impl GetData for SPEProfile {
    fn custom_raw_data_parser(&mut self, params: ReportParams) -> Result<Vec<ProcessedData>> {
        #[cfg(feature = "spe")]
        {
            unsafe {
                env::set_var("HOTLINE_DIR", params.data_dir.clone());
            }

            unsafe {
                env::set_var("HOTLINE_REPORT_DIR", params.report_dir.clone());
            }

            unsafe {
                build_report(); // writes csvs to ./data/
            }
        }

        let _ = generate_html_tables(
            &params,
            &format!("{}/data/completion_node_view.csv", params.report_dir.display()),
            &format!("{}/data/exec_lat_view.csv", params.report_dir.display()),
            &format!(
                "{}/data/issue_lat_view.csv",
                params.report_dir.display()
            ),
            &format!(
                "{}/data/x_lat_view.csv",
                params.report_dir.display()
            ),
            &format!("{}/data/branch_view.csv", params.report_dir.display()),
        );

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
#[cfg(feature = "spe")]
fn init_spe_profile() {
    let spe_profile_raw = SPEProfileRaw::new();
    let file_name = SPE_PROFILE_FILE_NAME.to_string();
    let dt = DataType::new(
        Data::SPEProfileRaw(spe_profile_raw.clone()),
        file_name.clone(),
        false,
    );
    let spe_perf_profile = SPEProfile::new();
    let js_file_name = file_name.clone() + ".js";
    let mut dv = DataVisualizer::new(
        ProcessedData::SPEProfile(spe_perf_profile.clone()),
        file_name.clone(),
        js_file_name,
        include_str!(concat!(env!("JS_DIR"), "/perf_profile.js")).to_string(),
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

use anyhow::Result;
use std::env;
use std::process::Command;

fn main() -> Result<()> {
    let _ = vergen::EmitBuilder::builder().git_sha(true).emit();

    println!("cargo:rerun-if-changed=src/hotline/*");
    println!("cargo:rerun-if-changed=package.json");
    println!("cargo:rerun-if-changed=package-lock.json");

    println!("cargo:rerun-if-changed=package.json");
    println!("cargo:rerun-if-changed=package-lock.json");

    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/lib/gcc/aarch64-linux-gnu/11");

    match Command::new("npm").arg("install").spawn() {
        Err(_proc) => {
            println!("Build requires npm, but it was not found. Please install Node >= 16.16.0.");
            std::process::exit(1);
        }
        Ok(mut child) => {
            let status = child.wait()?;
            if !status.success() {
                println!("Command \"npm install\" failed.");
                std::process::exit(1);
            }
        }
    }

    let jsdir = format!("{}/js", env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-env=JS_DIR={}", jsdir);
    println!("cargo:rerun-if-changed=src/html_files/");
    let status = Command::new("npm")
        .arg("exec")
        .arg("--")
        .arg("tsc")
        .arg("-p")
        .arg("src/html_files/")
        .arg("--outDir")
        .arg(jsdir)
        .spawn()?
        .wait()?;
    if !status.success() {
        println!("Failed to compile typescript.");
        std::process::exit(1);
    }

    #[cfg(feature = "spe")]
    {
    println!("cargo:rustc-link-search=native=/usr/aarch64-linux-gnu/lib");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=-static-libgcc");
    println!("cargo:rustc-link-arg=-static-libstdc++");

        let kernel_version = String::from_utf8(
            Command::new("uname")
                .arg("-r")
                .output()
                .expect("failed to get kernel version")
                .stdout,
        )
        .expect("invalid utf8")
        .trim()
        .to_string();

        cc::Build::new()
            .files([
                "src/hotline/bmiss_map.c",
                "src/hotline/btree.c",
                "src/hotline/config.c",
                "src/hotline/finode_map.c",
                "src/hotline/fname_binary_map.c",
                "src/hotline/fname_map.c",
                "src/hotline/hotline.c",
                "src/hotline/lat_map.c",
                "src/hotline/report.c",
                "src/hotline/sys.c",
                "src/hotline/vec.c",
                "src/hotline/tests/test_bmiss_map.c",
                "src/hotline/tests/test_config.c",
                "src/hotline/tests/test_finode_map.c",
                "src/hotline/tests/test_fname_binary_map.c",
                "src/hotline/tests/test_fname_map.c",
                "src/hotline/tests/test_lat_map.c",
                "src/hotline/tests/test.c",
            ])
            .includes(["src/hotline"])
            .flag("-D_GNU_SOURCE")
            // First add GCC's built-in headers
            .flag("-isystem")
            .flag("/usr/include")
            .flag("-isystem")
            .flag("/usr/include/aarch64-linux-gnu")
            .flag("-isystem")
            .flag("/usr/lib/gcc/aarch64-linux-gnu/11/include")
            // Then add system headers
            .flag("-isystem")
            .flag("/usr/include")
            .flag("-isystem")
            .flag("/usr/local/include")
            // Then add kernel headers
            .flag(&format!(
                "-I/usr/src/linux-headers-{}/generated/asm",
                kernel_version
            ))
            .flag(&format!(
                "-I/usr/src/linux-headers-{}/arch/arm64/include/generated/uapi",
                kernel_version
            ))
            .flag(&format!(
                "-I/usr/src/linux-headers-{}/arch/arm64/include",
                kernel_version
            ))
            .flag("-Wno-unused-parameter")
            .flag("-Wno-sign-compare")
            .flag("-Wno-missing-field-initializers")
            .opt_level(3)
            .static_flag(true)
            .static_crt(true)
            .compile("hotline");

        println!("cargo:rustc-link-lib=static=dw");
        println!("cargo:rustc-link-lib=static=elf");
        println!("cargo:rustc-link-lib=static=capstone");
        println!("cargo:rustc-link-lib=static=z");
        println!("cargo:rustc-link-lib=static=lzma");
        println!("cargo:rustc-link-lib=static=bz2");
        println!("cargo:rustc-link-lib=static=zstd");


        // println!("cargo:rustc-link-lib=static=c");
        // println!("cargo:rustc-link-lib=static=m");
        // println!("cargo:rustc-link-lib=static=gcc");
        // println!("cargo:rustc-link-lib=static=pthread");
        // println!("cargo:rustc-link-lib=static=dl");
        println!("Building with SPE support.");
    }

    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
    println!("cargo:rustc-link-arg=-Wl,--as-needed");
    Ok(())
}
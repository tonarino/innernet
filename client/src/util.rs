use colored::*;
use indoc::eprintdoc;
use innernet_shared::Interface;
use log::{Level, LevelFilter};
use std::{ffi::OsStr, io, path::Path, time::Duration};

static LOGGER: Logger = Logger;
struct Logger;

const BASE_MODULES: &[&str] = &["innernet", "innernet_shared"];

fn target_is_base(target: &str) -> bool {
    BASE_MODULES
        .iter()
        .any(|module| module == &target || target.starts_with(&format!("{module}::")))
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
            && (log::max_level() == LevelFilter::Trace || target_is_base(metadata.target()))
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let level_str = match record.level() {
                Level::Error => "[E]".red(),
                Level::Warn => "[!]".yellow(),
                Level::Info => "[*]".dimmed(),
                Level::Debug => "[D]".blue(),
                Level::Trace => "[T]".purple(),
            };
            if record.level() <= LevelFilter::Debug && !target_is_base(record.target()) {
                println!(
                    "{} {} {}",
                    level_str,
                    format!("[{}]", record.target()).dimmed(),
                    record.args()
                );
            } else {
                println!("{} {}", level_str, record.args());
            }
        }
    }

    fn flush(&self) {}
}

pub fn init_logger(verbosity: u8) {
    let level = match verbosity {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    log::set_max_level(level);
    log::set_logger(&LOGGER).unwrap();
}

pub fn human_duration(duration: Duration) -> String {
    match duration.as_secs() {
        n if n < 1 => "just now".cyan().to_string(),
        n if n < 60 => format!("{} {} ago", n, "seconds".cyan()),
        n if n < 60 * 60 => {
            let mins = n / 60;
            let secs = n % 60;
            format!(
                "{} {}, {} {} ago",
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
                secs,
                if secs == 1 { "second" } else { "seconds" }.cyan(),
            )
        },
        n => {
            let hours = n / (60 * 60);
            let mins = (n / 60) % 60;
            format!(
                "{} {}, {} {} ago",
                hours,
                if hours == 1 { "hour" } else { "hours" }.cyan(),
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
            )
        },
    }
}

pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;
    match bytes {
        n if n < 2 * KB => format!("{} {}", n, "B".cyan()),
        n if n < 2 * MB => format!("{:.2} {}", n as f64 / KB as f64, "KiB".cyan()),
        n if n < 2 * GB => format!("{:.2} {}", n as f64 / MB as f64, "MiB".cyan()),
        n if n < 2 * TB => format!("{:.2} {}", n as f64 / GB as f64, "GiB".cyan()),
        n => format!("{:.2} {}", n as f64 / TB as f64, "TiB".cyan()),
    }
}

pub fn permissions_helptext(config_dir: &Path, data_dir: &Path, e: &io::Error) {
    if e.raw_os_error() == Some(1) {
        let current_exe = std::env::current_exe()
            .ok()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "<innernet path>".into());
        eprintdoc!(
            "{}: innernet can't access the device info.

                You either need to run innernet as root, or give innernet CAP_NET_ADMIN capabilities:

                    sudo setcap cap_net_admin+eip {}
            ",
            "ERROR".bold().red(),
            current_exe
        );
    } else if e.kind() == io::ErrorKind::PermissionDenied {
        eprintdoc!(
            "{}: innernet can't access its config/data folders.

                You either need to run innernet as root, or give the user/group running innernet permissions
                to access {config} and {data}.

                For non-root permissions, it's recommended to create an \"innernet\" group, and run for example:

                    sudo chgrp -R innernet {config} {data}
                    sudo chmod -R g+rwX {config} {data}
            ",
            "ERROR".bold().red(),
            config = config_dir.to_string_lossy(),
            data = data_dir.to_string_lossy(),
        );
    }
}

pub fn all_installed(config_dir: &Path) -> Result<Vec<Interface>, std::io::Error> {
    // All errors are bubbled up when enumerating a directory
    let entries: Vec<_> = std::fs::read_dir(config_dir)?.collect::<Result<_, _>>()?;

    let installed: Vec<_> = entries
        .into_iter()
        .filter(|entry| match entry.file_type() {
            Ok(f) => f.is_file(),
            _ => false,
        })
        .filter_map(|entry| {
            let path = entry.path();
            match (path.extension(), path.file_stem()) {
                (Some(extension), Some(stem)) if extension == OsStr::new("conf") => {
                    Some(stem.to_string_lossy().to_string())
                },
                _ => None,
            }
        })
        .map(|name| name.parse())
        .collect::<Result<_, _>>()?;

    Ok(installed)
}

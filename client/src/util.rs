use crate::data_store::DataStore;
use colored::*;
use indoc::eprintdoc;
use log::{Level, LevelFilter};
use serde::{de::DeserializeOwned, Serialize};
use shared::{interface_config::ServerInfo, Interface, PeerDiff, INNERNET_PUBKEY_HEADER};
use std::{ffi::OsStr, io, path::Path, time::Duration};
use ureq::{Agent, AgentBuilder};

static LOGGER: Logger = Logger;
struct Logger;

const BASE_MODULES: &[&str] = &["innernet", "shared"];

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

pub fn init_logger(verbosity: u64) {
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

pub fn print_peer_diff(store: &DataStore, diff: &PeerDiff) {
    let public_key = diff.public_key().to_base64();

    let text = match (diff.old, diff.new) {
        (None, Some(_)) => "added".green(),
        (Some(_), Some(_)) => "modified".yellow(),
        (Some(_), None) => "removed".red(),
        _ => unreachable!("PeerDiff can't be None -> None"),
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_hostname = match diff.new {
        Some(peer) => Some(peer.name.clone()),
        None => store
            .peers()
            .iter()
            .find(|p| p.public_key == public_key)
            .map(|p| p.name.clone()),
    };
    let peer_name = peer_hostname.as_deref().unwrap_or("[unknown]");

    log::info!(
        "  peer {} ({}...) was {}.",
        peer_name.yellow(),
        &public_key[..10].dimmed(),
        text
    );

    for change in diff.changes() {
        log::debug!("    {}", change);
    }
}

pub fn all_installed(config_dir: &Path) -> Result<Vec<Interface>, std::io::Error> {
    // All errors are bubbled up when enumerating a directory
    let entries: Vec<_> = std::fs::read_dir(config_dir)?
        .into_iter()
        .collect::<Result<_, _>>()?;

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

pub struct Api<'a> {
    agent: Agent,
    server: &'a ServerInfo,
}

impl<'a> Api<'a> {
    pub fn new(server: &'a ServerInfo) -> Self {
        let agent = AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .build();
        Self { agent, server }
    }

    #[allow(clippy::result_large_err)]
    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, ureq::Error> {
        self.request::<(), _>(verb, endpoint, None)
    }

    #[allow(clippy::result_large_err)]
    pub fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, ureq::Error> {
        self.request(verb, endpoint, Some(form))
    }

    #[allow(clippy::result_large_err)]
    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, ureq::Error> {
        let request = self
            .agent
            .request(
                verb,
                &format!("http://{}/v1{}", self.server.internal_endpoint, endpoint),
            )
            .set(INNERNET_PUBKEY_HEADER, &self.server.public_key);

        let response = if let Some(form) = form {
            request.send_json(serde_json::to_value(form).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to serialize JSON request: {e}"),
                )
            })?)?
        } else {
            request.call()?
        };

        let mut response = response.into_string()?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        Ok(serde_json::from_str(&response).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to deserialize JSON response from the server: {}, response={}",
                    e, &response
                ),
            )
        })?)
    }
}

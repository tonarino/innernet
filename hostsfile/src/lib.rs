use std::{
    collections::HashMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, ErrorKind, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    result,
};

pub type Result<T> = result::Result<T, Box<dyn std::error::Error>>;

/// A custom error struct for this crate.
#[derive(Debug, Clone)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// `HostsBuilder` manages a section of /etc/hosts file that contains a list of IP to hostname
/// mappings. A hosts file can have multiple sections that are distinguished by tag names.
///
/// # Examples
///
/// ```no_run
/// use hostsfile::{HostsBuilder, Result};
/// # fn main() -> Result<()> {
/// let mut hosts = HostsBuilder::new("dns");
/// hosts.add_hostname("8.8.8.8".parse().unwrap(), "google-dns1");
/// hosts.add_hostname("8.8.4.4".parse().unwrap(), "google-dns2");
/// hosts.write_to("/tmp/hosts")?;
/// # Ok(())
/// # }
/// ```
///
/// `/tmp/hosts` will have a section:
///
/// ```text
/// # DO NOT EDIT dns BEGIN
/// 8.8.8.8 google-dns1
/// 8.8.4.4 google-dns2
/// # DO NOT EDIT dns END
/// ```
///
/// Another run of `HostsBuilder` with the same tag name overrides the section.
///
/// ```no_run
/// use hostsfile::{HostsBuilder, Result};
/// # fn main() -> Result<()> {
/// let mut hosts = HostsBuilder::new("dns");
/// hosts.add_hostnames("1.1.1.1".parse().unwrap(), &["cloudflare-dns", "apnic-dns"]);
/// hosts.write_to("/tmp/hosts")?;
/// # Ok(())
/// # }
/// ```
///
/// `/tmp/hosts` will have a section:
///
/// ```text
/// # DO NOT EDIT dns BEGIN
/// 1.1.1.1 cloudflare-dns apnic-dns
/// # DO NOT EDIT dns END
/// ```
///
/// On Windows the host file format is slightly different in this case:
/// ```text
/// # DO NOT EDIT dns BEGIN
/// 1.1.1.1 cloudflare-dns
/// 1.1.1.1 apnic-dns
/// # DO NOT EDIT dns END
/// ```
pub struct HostsBuilder {
    tag: String,
    hostname_map: HashMap<IpAddr, Vec<String>>,
}

impl HostsBuilder {
    /// Creates a new `HostsBuilder` with the given tag name. It corresponds to a section in the
    /// hosts file containing a list of IP to hostname mappings.
    pub fn new<S: Into<String>>(tag: S) -> Self {
        Self {
            tag: tag.into(),
            hostname_map: HashMap::new(),
        }
    }

    /// Adds a mapping of `ip` to `hostname`. If there hostnames associated with the IP already,
    /// the hostname will be appended to the list.
    pub fn add_hostname<S: ToString>(&mut self, ip: IpAddr, hostname: S) {
        let hostnames_dest = self.hostname_map.entry(ip).or_insert_with(Vec::new);
        hostnames_dest.push(hostname.to_string());
    }

    /// Adds a mapping of `ip` to a list of `hostname`s. If there hostnames associated with the IP
    /// already, the new hostnames will be appended to the list.
    pub fn add_hostnames<I: IntoIterator<Item = impl ToString>>(
        &mut self,
        ip: IpAddr,
        hostnames: I,
    ) {
        let hostnames_dest = self.hostname_map.entry(ip).or_insert_with(Vec::new);
        for hostname in hostnames.into_iter() {
            hostnames_dest.push(hostname.to_string());
        }
    }

    /// Inserts a new section to the system's default hosts file.  If there is a section with the
    /// same tag name already, it will be replaced with the new list instead.
    pub fn write(&self) -> io::Result<()> {
        let hosts_file = if cfg!(unix) {
            PathBuf::from("/etc/hosts")
        } else if cfg!(windows) {
            PathBuf::from(
                // according to https://support.microsoft.com/en-us/topic/how-to-reset-the-hosts-file-back-to-the-default-c2a43f9d-e176-c6f3-e4ef-3500277a6dae
                // the location depends on the environment variable %WinDir%.
                format!(
                    "{}\\System32\\Drivers\\Etc\\hosts",
                    std::env::var("WinDir").map_err(|_| io::Error::new(
                        ErrorKind::Other,
                        "WinDir environment variable missing".to_owned()
                    ))?
                ),
            )
        } else {
            return Err(io::Error::new(
                ErrorKind::Other,
                "unsupported operating system.".to_owned(),
            ));
        };

        if !hosts_file.exists() {
            return Err(ErrorKind::NotFound.into());
        }

        self.write_to(&hosts_file)
    }

    /// Inserts a new section to the specified hosts file.  If there is a section with the same tag
    /// name already, it will be replaced with the new list instead.
    ///
    /// On Windows, the format of one hostname per line will be used, all other systems will use
    /// the same format as Unix and Unix-like systems (i.e. allow multiple hostnames per line).
    pub fn write_to<P: AsRef<Path>>(&self, hosts_path: P) -> io::Result<()> {
        let hosts_path = hosts_path.as_ref();
        let begin_marker = format!("# DO NOT EDIT {} BEGIN", &self.tag);
        let end_marker = format!("# DO NOT EDIT {} END", &self.tag);

        let hosts_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(hosts_path)?;
        let mut lines = BufReader::new(hosts_file)
            .lines()
            .map(|line| line.unwrap())
            .collect::<Vec<_>>();

        let begin = lines.iter().position(|line| line.trim() == begin_marker);
        let end = lines.iter().position(|line| line.trim() == end_marker);

        let insert = match (begin, end) {
            (Some(begin), Some(end)) => {
                lines.drain(begin..end + 1);
                begin
            },
            (None, None) => {
                // Insert a blank line before a new section.
                if let Some(last_line) = lines.iter().last() {
                    if !last_line.is_empty() {
                        lines.push("".to_string());
                    }
                }
                lines.len()
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("start or end marker missing in {:?}", &hosts_path),
                ));
            },
        };

        // The tempfile should be in the same filesystem as the hosts file.
        let hosts_dir = hosts_path
            .parent()
            .expect("hosts file must be an absolute file path");
        let temp_dir = tempfile::Builder::new().tempdir_in(hosts_dir)?;
        let temp_path = temp_dir.path().join("hosts");

        // Copy the existing hosts file to preserve permissions.
        fs::copy(&hosts_path, &temp_path)?;

        let mut file = File::create(&temp_path)?;

        for line in &lines[..insert] {
            writeln!(&mut file, "{}", line)?;
        }
        if !self.hostname_map.is_empty() {
            writeln!(&mut file, "{}", begin_marker)?;
            for (ip, hostnames) in &self.hostname_map {
                if cfg!(windows) {
                    // windows only allows one hostname per line
                    for hostname in hostnames {
                        writeln!(&mut file, "{} {}", ip, hostname)?;
                    }
                } else {
                    // assume the same format as Unix
                    writeln!(&mut file, "{} {}", ip, hostnames.join(" "))?;
                }
            }
            writeln!(&mut file, "{}", end_marker)?;
        }
        for line in &lines[insert..] {
            writeln!(&mut file, "{}", line)?;
        }

        // Move the file atomically to avoid a partial state.
        fs::rename(&temp_path, &hosts_path)?;

        Ok(())
    }
}

use std::{
    collections::BTreeMap,
    fmt,
    fs::OpenOptions,
    io::{self, BufRead, BufReader, ErrorKind, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    result,
    time::{SystemTime, UNIX_EPOCH},
};

pub type Result<T> = result::Result<T, Box<dyn std::error::Error>>;

/// A custom error struct for this crate.
#[allow(dead_code)]
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
    hostname_map: BTreeMap<IpAddr, Vec<String>>,
}

impl HostsBuilder {
    /// Creates a new `HostsBuilder` with the given tag name. It corresponds to a section in the
    /// hosts file containing a list of IP to hostname mappings.
    pub fn new<S: Into<String>>(tag: S) -> Self {
        Self {
            tag: tag.into(),
            hostname_map: BTreeMap::new(),
        }
    }

    /// Adds a mapping of `ip` to `hostname`. If there hostnames associated with the IP already,
    /// the hostname will be appended to the list.
    pub fn add_hostname<S: ToString>(&mut self, ip: IpAddr, hostname: S) {
        let hostnames_dest = self.hostname_map.entry(ip).or_default();
        hostnames_dest.push(hostname.to_string());
    }

    /// Adds a mapping of `ip` to a list of `hostname`s. If there hostnames associated with the IP
    /// already, the new hostnames will be appended to the list.
    pub fn add_hostnames<I: IntoIterator<Item = impl ToString>>(
        &mut self,
        ip: IpAddr,
        hostnames: I,
    ) {
        let hostnames_dest = self.hostname_map.entry(ip).or_default();
        for hostname in hostnames.into_iter() {
            hostnames_dest.push(hostname.to_string());
        }
    }

    /// Inserts a new section to the system's default hosts file.  If there is a section with the
    /// same tag name already, it will be replaced with the new list instead.
    /// Returns true if the hosts file has changed.
    pub fn write(&self) -> io::Result<bool> {
        self.write_to(Self::default_path()?)
    }

    /// Returns the default hosts path based on the current OS.
    pub fn default_path() -> io::Result<PathBuf> {
        let hosts_file = if cfg!(unix) {
            PathBuf::from("/etc/hosts")
        } else if cfg!(windows) {
            PathBuf::from(
                // according to https://support.microsoft.com/en-us/topic/how-to-reset-the-hosts-file-back-to-the-default-c2a43f9d-e176-c6f3-e4ef-3500277a6dae
                // the location depends on the environment variable %WinDir%.
                format!(
                    "{}\\System32\\Drivers\\Etc\\hosts",
                    std::env::var("WinDir").map_err(|_| io::Error::other(
                        "WinDir environment variable missing".to_owned()
                    ))?
                ),
            )
        } else {
            return Err(io::Error::other(
                "unsupported operating system.".to_owned(),
            ));
        };

        if !hosts_file.exists() {
            return Err(ErrorKind::NotFound.into());
        }

        Ok(hosts_file)
    }

    pub fn get_temp_path(hosts_path: &Path) -> io::Result<PathBuf> {
        let hosts_dir = hosts_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "hosts path missing a parent folder",
            )
        })?;
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let mut temp_filename = hosts_path
            .file_name()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "hosts path missing a filename")
            })?
            .to_os_string();
        temp_filename.push(format!(".tmp{}", since_the_epoch.as_millis()));
        Ok(hosts_dir.with_file_name(temp_filename))
    }

    /// Inserts a new section to the specified hosts file.  If there is a section with the same tag
    /// name already, it will be replaced with the new list instead.
    ///
    /// `hosts_path` is the *full* path to write to, including the filename.
    ///
    /// On Windows, the format of one hostname per line will be used, all other systems will use
    /// the same format as Unix and Unix-like systems (i.e. allow multiple hostnames per line).
    ///
    /// Returns true if the hosts file has changed.
    pub fn write_to<P: AsRef<Path>>(&self, hosts_path: P) -> io::Result<bool> {
        let hosts_path = hosts_path.as_ref();
        if hosts_path.is_dir() {
            // TODO(jake): use io::ErrorKind::IsADirectory when it's stable.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hosts path was a directory",
            ));
        }

        let temp_path = Self::get_temp_path(hosts_path)?;

        let begin_marker = format!("# DO NOT EDIT {} BEGIN", &self.tag);
        let end_marker = format!("# DO NOT EDIT {} END", &self.tag);

        let hosts_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(hosts_path)?;
        let mut lines = BufReader::new(hosts_file)
            .lines()
            .map(|line| line.unwrap())
            .collect::<Vec<_>>();

        let begin = lines.iter().position(|line| line.trim() == begin_marker);
        let end = lines.iter().position(|line| line.trim() == end_marker);

        let mut lines_to_insert = vec![];
        if !self.hostname_map.is_empty() {
            lines_to_insert.push(begin_marker);
            for (ip, hostnames) in &self.hostname_map {
                if cfg!(windows) {
                    // windows only allows one hostname per line
                    for hostname in hostnames {
                        lines_to_insert.push(format!("{ip} {hostname}"));
                    }
                } else {
                    // assume the same format as Unix
                    lines_to_insert.push(format!("{} {}", ip, hostnames.join(" ")));
                }
            }
            lines_to_insert.push(end_marker);
        }

        let insert = match (begin, end) {
            (Some(begin), Some(end)) => {
                let old_section: Vec<String> = lines.drain(begin..end + 1).collect();

                if old_section == lines_to_insert {
                    return Ok(false);
                }

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

        let mut s = vec![];

        for line in &lines[..insert] {
            writeln!(s, "{line}")?;
        }

        // Append hostnames_map section
        for line in lines_to_insert {
            writeln!(s, "{line}")?;
        }

        for line in &lines[insert..] {
            writeln!(s, "{line}")?;
        }

        match Self::write_and_swap(&temp_path, hosts_path, &s) {
            Err(_) => {
                Self::write_clobber(hosts_path, &s)?;
                log::debug!("wrote hosts file with the clobber fallback strategy");
            },
            _ => {
                log::debug!("wrote hosts file with the write-and-swap strategy");
            },
        };

        Ok(true)
    }

    fn write_and_swap(temp_path: &Path, hosts_path: &Path, contents: &[u8]) -> io::Result<()> {
        // Copy the file we plan on modifying so its permissions and metadata are preserved.
        std::fs::copy(hosts_path, temp_path)?;

        #[cfg(feature = "selinux")]
        if selinux::current_mode() != selinux::SELinuxMode::NotRunning {
            log::trace!("SELinux is running; copying context");
            use selinux::SecurityContext;

            const FOLLOW_SYMBOLIC_LINKS: bool = false;
            const RAW_FORMAT: bool = false;
            match SecurityContext::of_path(hosts_path, FOLLOW_SYMBOLIC_LINKS, RAW_FORMAT) {
                Ok(Some(context)) => {
                    log::trace!(
                        "{} context is {:?}",
                        hosts_path.display(),
                        context.to_c_string()
                    );
                    if let Err(err) =
                        context.set_for_path(temp_path, FOLLOW_SYMBOLIC_LINKS, RAW_FORMAT)
                    {
                        log::warn!(
                            "SELinux context of {} ({:?}) could not be set \
                            ({} may become inaccessible due to permission errors): {:?}",
                            temp_path.display(),
                            context.to_c_string(),
                            hosts_path.display(),
                            err
                        );
                    }
                },
                Ok(None) => {
                    log::trace!("Hosts file {} had no SELinux context", hosts_path.display());
                },
                Err(err) => {
                    log::warn!(
                        "SELinux context of {} could not be retrieved \
                        (file may become inaccessible due to permission errors): {:?}",
                        hosts_path.display(),
                        err
                    );
                },
            }
        }

        Self::write_clobber(temp_path, contents)?;
        std::fs::rename(temp_path, hosts_path)?;
        Ok(())
    }

    fn write_clobber(hosts_path: &Path, contents: &[u8]) -> io::Result<()> {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(hosts_path)?
            .write_all(contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_temp_path_good() {
        let hosts_path = Path::new("/etc/hosts");
        let temp_path = HostsBuilder::get_temp_path(hosts_path).unwrap();
        println!("{temp_path:?}");
        assert!(temp_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("hosts.tmp"));
    }

    #[test]
    fn test_temp_path_invalid() {
        let hosts_path = Path::new("/");
        assert!(HostsBuilder::get_temp_path(hosts_path).is_err());
    }

    #[test]
    fn test_write() {
        let (mut temp_file, temp_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        temp_file.write_all(b"preexisting\ncontent").unwrap();
        let mut builder = HostsBuilder::new("foo");
        builder.add_hostname([1, 1, 1, 1].into(), "whatever");
        assert!(builder.write_to(&temp_path).unwrap());
        assert!(!builder.write_to(&temp_path).unwrap());

        let contents = std::fs::read_to_string(&temp_path).unwrap();
        println!("contents: {contents}");
        assert!(contents.starts_with("preexisting\ncontent"));
        assert!(contents.contains("# DO NOT EDIT foo BEGIN"));
        assert!(contents.contains("1.1.1.1 whatever"));
    }
}

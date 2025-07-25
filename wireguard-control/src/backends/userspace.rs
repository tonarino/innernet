use crate::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerInfo};

use std::{
    fmt::Write as _,
    fs,
    io::{self, prelude::*, BufReader},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime},
};

static VAR_RUN_PATH: &str = "/var/run/wireguard";
static RUN_PATH: &str = "/run/wireguard";

fn get_base_folder() -> io::Result<PathBuf> {
    if Path::new(VAR_RUN_PATH).exists() {
        Ok(Path::new(VAR_RUN_PATH).to_path_buf())
    } else if Path::new(RUN_PATH).exists() {
        Ok(Path::new(RUN_PATH).to_path_buf())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "WireGuard socket directory not found.",
        ))
    }
}

fn get_namefile(name: &InterfaceName) -> io::Result<PathBuf> {
    Ok(get_base_folder()?.join(format!("{}.name", name.as_str_lossy())))
}

fn get_socketfile(name: &InterfaceName) -> io::Result<PathBuf> {
    if cfg!(target_os = "linux") {
        Ok(get_base_folder()?.join(format!("{name}.sock")))
    } else {
        Ok(get_base_folder()?.join(format!("{}.sock", resolve_tun(name)?)))
    }
}

fn open_socket(name: &InterfaceName) -> io::Result<UnixStream> {
    UnixStream::connect(get_socketfile(name)?)
}

pub fn resolve_tun(name: &InterfaceName) -> io::Result<String> {
    let namefile = get_namefile(name)?;
    Ok(fs::read_to_string(namefile)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "WireGuard name file can't be read"))?
        .trim()
        .to_string())
}

pub fn delete_interface(name: &InterfaceName) -> io::Result<()> {
    fs::remove_file(get_socketfile(name)?).ok();
    fs::remove_file(get_namefile(name)?).ok();

    Ok(())
}

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {
    use std::ffi::OsStr;

    let mut interfaces = vec![];
    for entry in fs::read_dir(get_base_folder()?)? {
        let path = entry?.path();
        if path.extension() == Some(OsStr::new("name")) {
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|name| name.parse::<InterfaceName>().ok())
                .filter(|iface| open_socket(iface).is_ok());
            if let Some(iface) = stem {
                interfaces.push(iface);
            }
        }
    }

    Ok(interfaces)
}

struct ConfigParser {
    device_info: Device,
    current_peer: Option<PeerInfo>,
}

impl From<ConfigParser> for Device {
    fn from(parser: ConfigParser) -> Self {
        parser.device_info
    }
}

impl ConfigParser {
    /// Returns `None` if an invalid device name was provided.
    fn new(name: &InterfaceName) -> Self {
        let device_info = Device {
            name: *name,
            public_key: None,
            private_key: None,
            fwmark: None,
            listen_port: None,
            peers: vec![],
            linked_name: resolve_tun(name).ok(),
            backend: Backend::Userspace,
        };

        Self {
            device_info,
            current_peer: None,
        }
    }

    fn add_line(&mut self, line: &str) -> Result<(), std::io::Error> {
        use io::ErrorKind::InvalidData;

        let split: Vec<&str> = line.splitn(2, '=').collect();
        match &split[..] {
            [key, value] => self.add_pair(key, value),
            _ => Err(InvalidData.into()),
        }
    }

    fn add_pair(&mut self, key: &str, value: &str) -> Result<(), std::io::Error> {
        use io::ErrorKind::InvalidData;

        match key {
            "private_key" => {
                self.device_info.private_key = Some(Key::from_hex(value).map_err(|_| InvalidData)?);
                self.device_info.public_key = self
                    .device_info
                    .private_key
                    .as_ref()
                    .map(|k| k.get_public());
            },
            "listen_port" => {
                self.device_info.listen_port = Some(value.parse().map_err(|_| InvalidData)?)
            },
            "fwmark" => self.device_info.fwmark = Some(value.parse().map_err(|_| InvalidData)?),
            "public_key" => {
                let new_peer =
                    PeerInfo::from_public_key(Key::from_hex(value).map_err(|_| InvalidData)?);

                if let Some(finished_peer) = self.current_peer.replace(new_peer) {
                    self.device_info.peers.push(finished_peer);
                }
            },
            "preshared_key" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .config
                    .preshared_key = Some(Key::from_hex(value).map_err(|_| InvalidData)?);
            },
            "tx_bytes" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .stats
                    .tx_bytes = value.parse().map_err(|_| InvalidData)?
            },
            "rx_bytes" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .stats
                    .rx_bytes = value.parse().map_err(|_| InvalidData)?
            },
            "last_handshake_time_sec" => {
                let handshake_seconds: u64 = value.parse().map_err(|_| InvalidData)?;

                if handshake_seconds > 0 {
                    self.current_peer
                        .as_mut()
                        .ok_or(InvalidData)?
                        .stats
                        .last_handshake_time =
                        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(handshake_seconds));
                }
            },
            "allowed_ip" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .config
                    .allowed_ips
                    .push(value.parse().map_err(|_| InvalidData)?);
            },
            "persistent_keepalive_interval" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .config
                    .persistent_keepalive_interval = Some(value.parse().map_err(|_| InvalidData)?);
            },
            "endpoint" => {
                self.current_peer
                    .as_mut()
                    .ok_or(InvalidData)?
                    .config
                    .endpoint = Some(value.parse().map_err(|_| InvalidData)?);
            },
            "errno" => {
                // "errno" indicates an end of the stream, along with the error return code.
                if value != "0" {
                    return Err(std::io::Error::from_raw_os_error(
                        value
                            .parse()
                            .expect("Unable to parse userspace wg errno return code"),
                    ));
                }

                if let Some(finished_peer) = self.current_peer.take() {
                    self.device_info.peers.push(finished_peer);
                }
            },
            "protocol_version" | "last_handshake_time_nsec" => {},
            _ => println!("got unsupported info: {key}={value}"),
        }

        Ok(())
    }
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let mut sock = open_socket(name)?;
    sock.write_all(b"get=1\n\n")?;
    let mut reader = BufReader::new(sock);
    let mut buf = String::new();

    let mut parser = ConfigParser::new(name);

    loop {
        match reader.read_line(&mut buf)? {
            0 | 1 if buf == "\n" => break,
            _ => {
                parser.add_line(buf.trim_end())?;
                buf.clear();
            },
        };
    }

    Ok(parser.into())
}

/// Following the rough logic of wg-quick(8), use the wireguard-go userspace
/// implementation by default, but allow for an environment variable to choose
/// a different implementation.
///
/// wgctrl-rs will look for WG_USERSPACE_IMPLEMENTATION first, but will also
/// respect the WG_QUICK_USERSPACE_IMPLEMENTATION choice if the former isn't
/// available.
fn get_userspace_implementation() -> String {
    std::env::var("WG_USERSPACE_IMPLEMENTATION")
        .or_else(|_| std::env::var("WG_QUICK_USERSPACE_IMPLEMENTATION"))
        .unwrap_or_else(|_| "wireguard-go".to_string())
}

fn start_userspace_wireguard(iface: &InterfaceName) -> io::Result<Output> {
    let mut command = Command::new(get_userspace_implementation());
    let output = if cfg!(target_os = "linux") {
        command.args(&[iface.to_string()]).output()?
    } else {
        command
            .env("WG_TUN_NAME_FILE", format!("{VAR_RUN_PATH}/{iface}.name"))
            .args(["utun"])
            .output()?
    };
    if !output.status.success() {
        Err(io::ErrorKind::AddrNotAvailable.into())
    } else {
        Ok(output)
    }
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    // If we can't open a configuration socket to an existing interface, try starting it.
    let mut sock = match open_socket(iface) {
        Err(_) => {
            fs::create_dir_all(VAR_RUN_PATH)?;
            // Clear out any old namefiles if they didn't lead to a connected socket.
            let _ = fs::remove_file(get_namefile(iface)?);
            start_userspace_wireguard(iface)?;
            std::thread::sleep(Duration::from_millis(100));
            open_socket(iface)
                .map_err(|e| io::Error::new(e.kind(), format!("failed to open socket ({e})")))?
        },
        Ok(sock) => sock,
    };

    let mut request = String::from("set=1\n");

    if let Some(ref k) = builder.private_key {
        writeln!(request, "private_key={}", hex::encode(k.as_bytes())).ok();
    }

    if let Some(f) = builder.fwmark {
        writeln!(request, "fwmark={f}").ok();
    }

    if let Some(f) = builder.listen_port {
        writeln!(request, "listen_port={f}").ok();
    }

    if builder.replace_peers {
        writeln!(request, "replace_peers=true").ok();
    }

    for peer in &builder.peers {
        writeln!(
            request,
            "public_key={}",
            hex::encode(peer.public_key.as_bytes())
        )
        .ok();

        if peer.replace_allowed_ips {
            writeln!(request, "replace_allowed_ips=true").ok();
        }

        if peer.remove_me {
            writeln!(request, "remove=true").ok();
        }

        if let Some(ref k) = peer.preshared_key {
            writeln!(request, "preshared_key={}", hex::encode(k.as_bytes())).ok();
        }

        if let Some(endpoint) = peer.endpoint {
            writeln!(request, "endpoint={endpoint}").ok();
        }

        if let Some(keepalive_interval) = peer.persistent_keepalive_interval {
            writeln!(
                request,
                "persistent_keepalive_interval={keepalive_interval}"
            )
            .ok();
        }

        for allowed_ip in &peer.allowed_ips {
            writeln!(
                request,
                "allowed_ip={}/{}",
                allowed_ip.address, allowed_ip.cidr
            )
            .ok();
        }
    }

    request.push('\n');

    sock.write_all(request.as_bytes())?;

    let mut reader = BufReader::new(sock);
    let mut line = String::new();

    reader.read_line(&mut line)?;
    let split: Vec<&str> = line.trim_end().splitn(2, '=').collect();
    match &split[..] {
        ["errno", "0"] => Ok(()),
        ["errno", val] => {
            println!("ERROR {val}");
            Err(io::ErrorKind::InvalidInput.into())
        },
        _ => Err(io::ErrorKind::Other.into()),
    }
}

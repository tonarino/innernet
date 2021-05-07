use crate::Error;
use colored::*;
use serde::{Deserialize, Serialize};
use shared::{ensure_dirs_exist, Cidr, IoErrorContext, Peer, CLIENT_DATA_PATH};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use wgctrl::InterfaceName;

#[derive(Debug)]
pub struct DataStore {
    file: File,
    contents: Contents,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum Contents {
    #[serde(rename = "1")]
    V1 { peers: Vec<Peer>, cidrs: Vec<Cidr> },
}

impl DataStore {
    pub(self) fn open_with_path<P: AsRef<Path>>(path: P, create: bool) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .open(path)
            .with_path(path)?;

        if shared::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }

        let mut json = String::new();
        file.read_to_string(&mut json).with_path(path)?;
        let contents = serde_json::from_str(&json).unwrap_or_else(|_| Contents::V1 {
            peers: vec![],
            cidrs: vec![],
        });

        Ok(Self { file, contents })
    }

    pub fn get_path(interface: &InterfaceName) -> PathBuf {
        CLIENT_DATA_PATH
            .join(interface.to_string())
            .with_extension("json")
    }

    fn _open(interface: &InterfaceName, create: bool) -> Result<Self, Error> {
        ensure_dirs_exist(&[*CLIENT_DATA_PATH])?;
        Self::open_with_path(Self::get_path(interface), create)
    }

    pub fn open(interface: &InterfaceName) -> Result<Self, Error> {
        Self::_open(interface, false)
    }

    pub fn open_or_create(interface: &InterfaceName) -> Result<Self, Error> {
        Self::_open(interface, true)
    }

    pub fn peers(&self) -> &[Peer] {
        match &self.contents {
            Contents::V1 { peers, .. } => peers,
        }
    }

    /// Add new peers to the PeerStore, never deleting old ones.
    ///
    /// This is done as a protective measure, validating that the (IP, PublicKey) tuple
    /// of the interface's peers never change, i.e. "pinning" them. This prevents a compromised
    /// server from impersonating an existing peer.
    ///
    /// Note, however, that this does not prevent a compromised server from adding a new
    /// peer under its control, of course.
    pub fn add_peers(&mut self, new_peers: Vec<Peer>) -> Result<(), Error> {
        let peers = match &mut self.contents {
            Contents::V1 { ref mut peers, .. } => peers,
        };

        for new_peer in new_peers {
            if let Some(existing_peer) = peers.iter_mut().find(|p| p.ip == new_peer.ip) {
                if existing_peer.public_key != new_peer.public_key {
                    return Err(
                        "PINNING ERROR: New peer has same IP but different public key.".into(),
                    );
                } else {
                    *existing_peer = new_peer;
                }
            } else {
                peers.push(new_peer);
            }
        }

        Ok(())
    }

    pub fn cidrs(&self) -> &[Cidr] {
        match &self.contents {
            Contents::V1 { cidrs, .. } => cidrs,
        }
    }

    pub fn set_cidrs(&mut self, new_cidrs: Vec<Cidr>) {
        match &mut self.contents {
            Contents::V1 { ref mut cidrs, .. } => *cidrs = new_cidrs,
        }
    }

    pub fn write(&mut self) -> Result<(), Error> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file
            .write_all(serde_json::to_string_pretty(&self.contents)?.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use shared::{Cidr, CidrContents, Peer, PeerContents};
    lazy_static! {
        static ref BASE_PEERS: Vec<Peer> = vec![Peer {
            id: 0,
            contents: PeerContents {
                name: "blah".parse().unwrap(),
                ip: "10.0.0.1".parse().unwrap(),
                cidr_id: 1,
                public_key: "abc".to_string(),
                endpoint: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                persistent_keepalive_interval: None,
                invite_expires: None,
            }
        }];
        static ref BASE_CIDRS: Vec<Cidr> = vec![Cidr {
            id: 1,
            contents: CidrContents {
                name: "cidr".to_string(),
                cidr: "10.0.0.0/24".parse().unwrap(),
                parent: None
            }
        }];
    }
    fn setup_basic_store(dir: &Path) {
        let mut store = DataStore::open_with_path(&dir.join("peer_store.json"), true).unwrap();

        println!("{:?}", store);
        assert_eq!(0, store.peers().len());
        assert_eq!(0, store.cidrs().len());

        store.add_peers(BASE_PEERS.to_owned()).unwrap();
        store.set_cidrs(BASE_CIDRS.to_owned());
        store.write().unwrap();
    }

    #[test]
    fn test_sanity() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = DataStore::open_with_path(&dir.path().join("peer_store.json"), false).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
        assert_eq!(store.cidrs(), &*BASE_CIDRS);
    }

    #[test]
    fn test_pinning() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(&dir.path().join("peer_store.json"), false).unwrap();

        // Should work, since peer is unmodified.
        store.add_peers(BASE_PEERS.clone()).unwrap();

        let mut modified = BASE_PEERS.clone();
        modified[0].contents.public_key = "foo".to_string();

        // Should NOT work, since peer is unmodified.
        assert!(store.add_peers(modified).is_err());
    }

    #[test]
    fn test_peer_persistence() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(&dir.path().join("peer_store.json"), false).unwrap();

        // Should work, since peer is unmodified.
        store.add_peers(vec![]).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
    }
}

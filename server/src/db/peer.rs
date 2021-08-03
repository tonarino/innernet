use super::DatabaseCidr;
use crate::ServerError;
use lazy_static::lazy_static;
use regex::Regex;
use rusqlite::{params, Connection};
use shared::{Peer, PeerContents, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::{Duration, SystemTime},
};
use structopt::lazy_static;

pub static CREATE_TABLE_SQL: &str = "CREATE TABLE peers (
      id                  INTEGER PRIMARY KEY,
      name                TEXT NOT NULL UNIQUE,         /* The canonical name for the peer in canonical hostname(7) format. */
      ip                  TEXT NOT NULL UNIQUE,         /* The WireGuard-internal IP address assigned to the peer.          */
      public_key          TEXT NOT NULL UNIQUE,         /* The WireGuard public key of the peer.                            */
      endpoint            TEXT,                         /* The optional external endpoint ([ip]:[port]) of the peer.        */
      cidr_id             INTEGER NOT NULL,             /* The ID of the peer's parent CIDR.                                */
      is_admin            INTEGER DEFAULT 0 NOT NULL,   /* Admin capabilities are per-peer, not per-CIDR.                   */
      is_disabled         INTEGER DEFAULT 0 NOT NULL,   /* Is the peer disabled? (peers cannot be deleted)                  */
      is_redeemed         INTEGER DEFAULT 0 NOT NULL,   /* Has the peer redeemed their invite yet?                          */
      invite_expires      INTEGER,                      /* The UNIX time that an invited peer can no longer redeem.         */
      endpoint_candidates TEXT,                         /* A list of additional endpoints that peers can use to connect.    */
      FOREIGN KEY (cidr_id)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

lazy_static! {
    /// Regex to match the requirements of hostname(7), needed to have peers also be reachable hostnames.
    /// Note that the full length also must be maximum 63 characters, which this regex does not check.
    static ref PEER_NAME_REGEX: Regex = Regex::new(r"^([a-z0-9]-?)*[a-z0-9]$").unwrap();
}

#[derive(Debug)]
pub struct DatabasePeer {
    pub inner: Peer,
}

impl From<Peer> for DatabasePeer {
    fn from(inner: Peer) -> Self {
        Self { inner }
    }
}

impl Deref for DatabasePeer {
    type Target = Peer;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabasePeer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabasePeer {
    pub fn create(conn: &Connection, contents: PeerContents) -> Result<Self, ServerError> {
        let PeerContents {
            name,
            ip,
            cidr_id,
            public_key,
            endpoint,
            is_admin,
            is_disabled,
            is_redeemed,
            invite_expires,
            ..
        } = &contents;
        log::info!("creating peer {:?}", contents);

        if !Self::is_valid_name(name) {
            log::warn!("peer name is invalid, must conform to hostname(7) requirements.");
            return Err(ServerError::InvalidQuery);
        }

        let cidr = DatabaseCidr::get(conn, *cidr_id)?;
        if !cidr.cidr.contains(*ip) {
            log::warn!("tried to add peer with IP outside of parent CIDR range.");
            return Err(ServerError::InvalidQuery);
        }

        if !cidr.cidr.is_assignable(*ip) {
            println!("Peer IP cannot be the network or broadcast IP of CIDRs with network prefixes under 31.");
            return Err(ServerError::InvalidQuery);
        }

        let invite_expires = invite_expires
            .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .flatten()
            .map(|t| t.as_secs());

        conn.execute(
            "INSERT INTO peers (name, ip, cidr_id, public_key, endpoint, is_admin, is_disabled, is_redeemed, invite_expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &**name,
                ip.to_string(),
                cidr_id,
                &public_key,
                endpoint.as_ref().map(|endpoint| endpoint.to_string()),
                is_admin,
                is_disabled,
                is_redeemed,
                invite_expires,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Peer { id, contents }.into())
    }

    fn is_valid_name(name: &str) -> bool {
        name.len() < 64 && PEER_NAME_REGEX.is_match(name)
    }

    /// Update self with new contents, validating them and updating the backend in the process.
    pub fn update(&mut self, conn: &Connection, contents: PeerContents) -> Result<(), ServerError> {
        if !Self::is_valid_name(&contents.name) {
            log::warn!("peer name is invalid, must conform to hostname(7) requirements.");
            return Err(ServerError::InvalidQuery);
        }

        // We will only allow updates of certain fields at this point, disregarding any requests
        // for changes of IP address, public key, or parent CIDR, for security reasons.
        //
        // In the future, we may allow re-assignments of peers to new CIDRs, but it's easiest to
        // disregard that case for now to prevent possible attacks.
        let new_contents = PeerContents {
            name: contents.name,
            endpoint: contents.endpoint,
            is_admin: contents.is_admin,
            is_disabled: contents.is_disabled,
            ..self.contents.clone()
        };

        conn.execute(
            "UPDATE peers SET
                name = ?1,
                endpoint = ?2,
                is_admin = ?3,
                is_disabled = ?4
            WHERE id = ?5",
            params![
                &*new_contents.name,
                new_contents
                    .endpoint
                    .as_ref()
                    .map(|endpoint| endpoint.to_string()),
                new_contents.is_admin,
                new_contents.is_disabled,
                self.id,
            ],
        )?;

        self.contents = new_contents;
        Ok(())
    }

    pub fn disable(conn: &Connection, id: i64) -> Result<(), ServerError> {
        match conn.execute(
            "UPDATE peers SET is_disabled = 1 WHERE id = ?1",
            params![id],
        )? {
            0 => Err(ServerError::NotFound),
            _ => Ok(()),
        }
    }

    pub fn redeem(&mut self, conn: &Connection, pubkey: &str) -> Result<(), ServerError> {
        if self.is_redeemed {
            return Err(ServerError::Gone);
        }

        if matches!(self.invite_expires, Some(time) if time < SystemTime::now()) {
            return Err(ServerError::Unauthorized);
        }

        match conn.execute(
            "UPDATE peers SET is_redeemed = 1, public_key = ?1 WHERE id = ?2 AND is_redeemed = 0",
            params![pubkey, self.id],
        )? {
            0 => Err(ServerError::NotFound),
            _ => {
                self.contents.public_key = pubkey.into();
                self.contents.is_redeemed = true;
                Ok(())
            },
        }
    }

    fn from_row(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let id = row.get(0)?;
        let name = row
            .get::<_, String>(1)?
            .parse()
            .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
        let ip: IpAddr = row
            .get::<_, String>(2)?
            .parse()
            .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
        let cidr_id = row.get(3)?;
        let public_key = row.get(4)?;
        let endpoint = row
            .get::<_, Option<String>>(5)?
            .and_then(|endpoint| endpoint.parse().ok());
        let is_admin = row.get(6)?;
        let is_disabled = row.get(7)?;
        let is_redeemed = row.get(8)?;
        let invite_expires = row
            .get::<_, Option<u64>>(9)?
            .map(|unixtime| SystemTime::UNIX_EPOCH + Duration::from_secs(unixtime));

        let persistent_keepalive_interval = Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS);

        Ok(Peer {
            id,
            contents: PeerContents {
                name,
                ip,
                cidr_id,
                public_key,
                endpoint,
                persistent_keepalive_interval,
                is_admin,
                is_disabled,
                is_redeemed,
                invite_expires,
            },
        }
        .into())
    }

    pub fn get(conn: &Connection, id: i64) -> Result<Self, ServerError> {
        let result = conn.query_row(
            "SELECT
            id, name, ip, cidr_id, public_key, endpoint, is_admin, is_disabled, is_redeemed, invite_expires
            FROM peers
            WHERE id = ?1",
            params![id],
            Self::from_row,
        )?;

        Ok(result)
    }

    pub fn get_from_ip(conn: &Connection, ip: IpAddr) -> Result<Self, rusqlite::Error> {
        let result = conn.query_row(
            "SELECT
            id, name, ip, cidr_id, public_key, endpoint, is_admin, is_disabled, is_redeemed, invite_expires
            FROM peers
            WHERE ip = ?1",
            params![ip.to_string()],
            Self::from_row,
        )?;

        Ok(result)
    }

    pub fn get_all_allowed_peers(&self, conn: &Connection) -> Result<Vec<Self>, ServerError> {
        // This query is a handful, so an explanation of what's happening, and what each CTE does (https://sqlite.org/lang_with.html):
        //
        // 1. parent_of: Enumerate all ancestor CIDRs of the CIDR associated with peer.
        // 2. associated: Enumerate all auth associations between any of the above enumerated CIDRs.
        // 3. associated_subcidrs: For each association, list all peers by enumerating down each
        //    associated CIDR's children and listing any peers belonging to them.
        //
        // NOTE that a forced association is created with the special "infra" CIDR with id 2 (1 being the root).
        let mut stmt = conn.prepare_cached(
            "WITH
                parent_of(id, parent) AS (
                    SELECT id, parent FROM cidrs WHERE id = ?1
                    UNION ALL
                    SELECT cidrs.id, cidrs.parent FROM cidrs JOIN parent_of ON parent_of.parent = cidrs.id
                ),
                associated(cidr_id) as (
                    SELECT associations.cidr_id_2 FROM associations, parent_of WHERE associations.cidr_id_1 = parent_of.id
                    UNION
                    SELECT associations.cidr_id_1 FROM associations, parent_of WHERE associations.cidr_id_2 = parent_of.id
                ),
                associated_subcidrs(cidr_id) AS (
                    VALUES(?1), (2)
                    UNION
                    SELECT cidr_id FROM associated
                    UNION
                    SELECT id FROM cidrs, associated_subcidrs WHERE cidrs.parent=associated_subcidrs.cidr_id
                )
                SELECT DISTINCT peers.id, peers.name, peers.ip, peers.cidr_id, peers.public_key, peers.endpoint, peers.is_admin, peers.is_disabled, peers.is_redeemed, peers.invite_expires
                FROM peers
                JOIN associated_subcidrs ON peers.cidr_id=associated_subcidrs.cidr_id
                WHERE peers.is_disabled = 0 AND peers.is_redeemed = 1;",
        )?;
        let peers = stmt
            .query_map(params![self.cidr_id], Self::from_row)?
            .collect::<Result<_, _>>()?;
        Ok(peers)
    }

    pub fn list(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let mut stmt = conn.prepare_cached(
            "SELECT id, name, ip, cidr_id, public_key, endpoint, is_admin, is_disabled, is_redeemed, invite_expires FROM peers",
        )?;
        let peer_iter = stmt.query_map(params![], Self::from_row)?;

        Ok(peer_iter.collect::<Result<_, _>>()?)
    }

    pub fn delete_expired_invites(conn: &Connection) -> Result<usize, ServerError> {
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Something is horribly wrong with system time.");
        let deleted = conn.execute(
            "DELETE FROM peers
            WHERE is_redeemed = 0 AND invite_expires < ?1",
            params![unix_now.as_secs()],
        )?;

        Ok(deleted)
    }
}

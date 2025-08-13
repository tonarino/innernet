use crate::ServerError;
use innernet_shared::{Cidr, CidrContents};
use ipnet::IpNet;
use rusqlite::{params, Connection};
use std::ops::{Deref, DerefMut};

pub static CREATE_TABLE_SQL: &str = "CREATE TABLE cidrs (
      id               INTEGER PRIMARY KEY,
      name             TEXT NOT NULL UNIQUE,
      ip               TEXT NOT NULL,
      prefix           INTEGER NOT NULL,
      parent           INTEGER REFERENCES cidrs,
      UNIQUE(ip, prefix),
      FOREIGN KEY (parent)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

pub struct DatabaseCidr {
    inner: Cidr,
}

impl From<Cidr> for DatabaseCidr {
    fn from(inner: Cidr) -> Self {
        Self { inner }
    }
}

impl Deref for DatabaseCidr {
    type Target = Cidr;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabaseCidr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabaseCidr {
    pub fn create(conn: &Connection, contents: CidrContents) -> Result<Cidr, ServerError> {
        let CidrContents { name, cidr, parent } = &contents;

        log::debug!("creating {:?}", contents);

        let attached_peers = conn.query_row(
            "SELECT COUNT(*) FROM peers WHERE cidr_id = ?1",
            params![parent],
            |row| row.get::<_, u32>(0),
        )?;
        if attached_peers > 0 {
            log::warn!("tried to add a CIDR to a parent that has peers assigned to it.");
            return Err(ServerError::InvalidQuery);
        }

        if let Some(parent_id) = parent {
            let cidrs = Self::list(conn)?;

            let closest_parent = cidrs
                .iter()
                .filter(|current| current.cidr.contains(cidr))
                .max_by_key(|current| current.cidr.prefix_len());

            if let Some(closest_parent) = closest_parent {
                if closest_parent.id != *parent_id {
                    log::warn!("tried to add a CIDR at the incorrect place in the tree (should be added to {}).", closest_parent.name);
                    return Err(ServerError::InvalidQuery);
                }
            } else {
                log::warn!("tried to add a CIDR outside of the root network range.");
                return Err(ServerError::InvalidQuery);
            }

            let parent_cidr = Self::get(conn, *parent_id)?.cidr;
            if !parent_cidr.contains(&cidr.network()) || !parent_cidr.contains(&cidr.broadcast()) {
                log::warn!("tried to add a CIDR with a network range outside of its parent.");
                return Err(ServerError::InvalidQuery);
            }
        }

        let overlapping_sibling = Self::list(conn)?
            .iter()
            .filter(|current| current.parent == *parent)
            .map(|sibling| sibling.cidr)
            .any(|sibling| {
                cidr.contains(&sibling.network())
                    || cidr.contains(&sibling.broadcast())
                    || sibling.contains(&cidr.network())
                    || sibling.contains(&cidr.broadcast())
            });

        if overlapping_sibling {
            log::warn!("tried to add a CIDR that overlaps with a sibling.");
            return Err(ServerError::InvalidQuery);
        }

        conn.execute(
            "INSERT INTO cidrs (name, ip, prefix, parent)
              VALUES (?1, ?2, ?3, ?4)",
            params![
                name,
                cidr.addr().to_string(),
                cidr.prefix_len() as i32,
                parent
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Cidr { id, contents })
    }

    /// Update self with new contents, validating them and updating the backend in the process.
    /// Currently this only supports updating the name and ignores changes to any other field.
    pub fn update(&mut self, conn: &Connection, contents: CidrContents) -> Result<(), ServerError> {
        let new_contents = CidrContents {
            name: contents.name,
            ..self.contents.clone()
        };

        conn.execute(
            "UPDATE cidrs SET name = ?2 WHERE id = ?1",
            params![self.id, &*new_contents.name,],
        )?;

        self.contents = new_contents;
        Ok(())
    }

    pub fn delete(conn: &Connection, id: i64) -> Result<(), ServerError> {
        conn.execute("DELETE FROM cidrs WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn from_row(row: &rusqlite::Row) -> Result<Cidr, rusqlite::Error> {
        let id = row.get(0)?;
        let name = row.get(1)?;
        let ip_str: String = row.get(2)?;
        let prefix = row.get(3)?;
        let ip = ip_str
            .parse()
            .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
        let cidr = IpNet::new(ip, prefix).map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
        let parent = row.get(4)?;
        Ok(Cidr {
            id,
            contents: CidrContents { name, cidr, parent },
        })
    }

    pub fn get(conn: &Connection, id: i64) -> Result<Cidr, ServerError> {
        Ok(conn.query_row(
            "SELECT id, name, ip, prefix, parent FROM cidrs WHERE id = ?1",
            params![id],
            Self::from_row,
        )?)
    }

    pub fn list(conn: &Connection) -> Result<Vec<Cidr>, ServerError> {
        let mut stmt = conn.prepare_cached("SELECT id, name, ip, prefix, parent FROM cidrs")?;
        let cidr_iter = stmt.query_map(params![], Self::from_row)?;

        Ok(cidr_iter.collect::<Result<Vec<_>, rusqlite::Error>>()?)
    }
}

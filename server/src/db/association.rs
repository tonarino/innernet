//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use crate::ServerError;
use rusqlite::{params, Connection};
use shared::{Association, AssociationContents};
use std::ops::{Deref, DerefMut};

pub static CREATE_TABLE_SQL: &str = "CREATE TABLE associations (
      id         INTEGER PRIMARY KEY,
      cidr_id_1  INTEGER NOT NULL,
      cidr_id_2  INTEGER NOT NULL,
      UNIQUE(cidr_id_1, cidr_id_2),
      FOREIGN KEY (cidr_id_1)
         REFERENCES cidrs (id) 
            ON UPDATE RESTRICT
            ON DELETE RESTRICT,
      FOREIGN KEY (cidr_id_2)
         REFERENCES cidrs (id) 
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

#[derive(Debug)]
pub struct DatabaseAssociation {
    pub inner: Association,
}

impl From<Association> for DatabaseAssociation {
    fn from(inner: Association) -> Self {
        Self { inner }
    }
}

impl Deref for DatabaseAssociation {
    type Target = Association;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabaseAssociation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabaseAssociation {
    pub fn create(
        conn: &Connection,
        contents: AssociationContents,
    ) -> Result<Association, ServerError> {
        let AssociationContents {
            cidr_id_1,
            cidr_id_2,
        } = &contents;

        conn.execute(
            "INSERT INTO associations (cidr_id_1, cidr_id_2)
              VALUES (?1, ?2)",
            params![cidr_id_1, cidr_id_2],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Association { id, contents })
    }

    pub fn delete(conn: &Connection, id: i64) -> Result<(), ServerError> {
        conn.execute("DELETE FROM associations WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list(conn: &Connection) -> Result<Vec<Association>, ServerError> {
        let mut stmt = conn.prepare_cached("SELECT id, cidr_id_1, cidr_id_2 FROM associations")?;
        let auth_iter = stmt.query_map(params![], |row| {
            let id = row.get(0)?;
            let cidr_id_1 = row.get(1)?;
            let cidr_id_2 = row.get(2)?;
            Ok(Association {
                id,
                contents: AssociationContents {
                    cidr_id_1,
                    cidr_id_2,
                },
            })
        })?;

        Ok(auth_iter.collect::<Result<Vec<_>, rusqlite::Error>>()?)
    }
}

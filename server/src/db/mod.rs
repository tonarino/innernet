pub mod association;
pub mod cidr;
pub mod peer;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;
use rusqlite::params;

const INVITE_EXPIRATION_VERSION: usize = 1;

pub const CURRENT_VERSION: usize = INVITE_EXPIRATION_VERSION;

pub fn auto_migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let old_version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

    if old_version < INVITE_EXPIRATION_VERSION {
        conn.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    conn.pragma_update(None, "user_version", &CURRENT_VERSION)?;
    if old_version != CURRENT_VERSION {
        log::info!(
            "migrated db version from {} to {}",
            old_version,
            CURRENT_VERSION
        );
    }

    Ok(())
}

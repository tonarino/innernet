pub mod association;
pub mod cidr;
pub mod peer;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;
use rusqlite::params;

const INVITE_EXPIRATION_VERSION: usize = 1;
const ENDPOINT_CANDIDATES_VERSION: usize = 2;
const CIDR_DISABLED_VERSION: usize = 3;

pub const CURRENT_VERSION: usize = CIDR_DISABLED_VERSION;

pub fn auto_migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let old_version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    log::debug!("user_version: {}", old_version);

    if old_version < INVITE_EXPIRATION_VERSION {
        conn.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    if old_version < ENDPOINT_CANDIDATES_VERSION {
        conn.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", params![])?;
    }

    if old_version < CIDR_DISABLED_VERSION {
        conn.execute(
            "ALTER TABLE cidrs ADD COLUMN is_disabled INTEGER DEFAULT 0 NOT NULL",
            params![],
        )?;
    }

    if old_version != CURRENT_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        log::info!(
            "migrated db version from {} to {}",
            old_version,
            CURRENT_VERSION
        );
    }

    Ok(())
}

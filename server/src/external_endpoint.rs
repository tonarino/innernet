use crate::{
    db::{peer::SERVER_PEER_ID, DatabasePeer},
    open_database_connection, ServerConfig,
};
use anyhow::{anyhow, Error};
use clap::Parser;
use innernet_shared::{prompts, Endpoint};
use wireguard_control::InterfaceName;

#[derive(Debug, Default, Clone, PartialEq, Eq, Parser)]
pub struct SetExternalEndpointOpts {
    /// The server's primary external endpoint (ex: 100.100.100.100:51820)
    #[clap(long)]
    pub external_endpoint: Option<Endpoint>,

    /// The server's IPv6 external endpoint (ex: [2001:db8::1]:51820)
    #[clap(
        long,
        conflicts_with = "unset_external_endpoint_v6",
        value_parser = Endpoint::parse_ipv6
    )]
    pub external_endpoint_v6: Option<Endpoint>,

    /// Remove the server's IPv6 external endpoint
    #[clap(long)]
    pub unset_external_endpoint_v6: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

/// Changes the external endpoints advertised in new invitations and to connected peers.
pub fn set_external_endpoint(
    interface: &InterfaceName,
    conf: &ServerConfig,
    opts: SetExternalEndpointOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let mut server_peer = DatabasePeer::get(&conn, SERVER_PEER_ID)?;
    let current_endpoint_v6 = server_peer.ipv6_external_endpoint().cloned();

    let interactive = opts.external_endpoint.is_none()
        && opts.external_endpoint_v6.is_none()
        && !opts.unset_external_endpoint_v6;

    let endpoint = match opts.external_endpoint {
        Some(endpoint) => endpoint,
        None if interactive => prompts::input_external_endpoint(server_peer.endpoint.clone())?,
        None => server_peer.endpoint.clone().ok_or_else(|| {
            anyhow!("the server has no external endpoint; pass --external-endpoint")
        })?,
    };
    let endpoint_v6 = match opts.external_endpoint_v6 {
        _ if opts.unset_external_endpoint_v6 => None,
        Some(endpoint_v6) => Some(endpoint_v6),
        None if interactive => prompts::input_external_endpoint_v6(current_endpoint_v6)?,
        None => current_endpoint_v6,
    };

    let endpoint_v6_display = endpoint_v6
        .as_ref()
        .map_or_else(|| "none".to_string(), ToString::to_string);
    if !opts.yes
        && !prompts::confirm(&format!(
            "Set external endpoint to {endpoint} and IPv6 external endpoint to \
             {endpoint_v6_display}?"
        ))?
    {
        println!("exited without changing the external endpoint.");
        return Ok(());
    }

    let mut contents = server_peer.contents.clone();
    contents.endpoint = Some(endpoint);
    contents.candidates.retain(|candidate| !candidate.is_ipv6());
    contents.candidates.extend(endpoint_v6);
    server_peer
        .update(&conn, contents)
        .map_err(|e| anyhow!("failed to update the server's external endpoint: {e}"))?;

    println!("External endpoint updated. New invitations will use it.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialize::{init_wizard, InitializeOpts};
    use tempfile::TempDir;

    fn endpoint(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    fn init(external_endpoint_v6: Option<&str>) -> (TempDir, ServerConfig, InterfaceName) {
        let dir = tempfile::tempdir().unwrap();
        let conf = ServerConfig::new(dir.path().to_path_buf(), dir.path().to_path_buf());
        let opts = InitializeOpts {
            network_name: Some("test".parse().unwrap()),
            network_cidr: Some("10.42.0.0/16".parse().unwrap()),
            external_endpoint: Some(endpoint("203.0.113.1:51820")),
            external_endpoint_v6: external_endpoint_v6.map(endpoint),
            listen_port: Some(51820),
            auto_external_endpoint: false,
        };
        init_wizard(&conf, opts).unwrap();
        (dir, conf, "test".parse().unwrap())
    }

    fn set(conf: &ServerConfig, interface: &InterfaceName, opts: SetExternalEndpointOpts) {
        set_external_endpoint(
            interface,
            conf,
            SetExternalEndpointOpts { yes: true, ..opts },
        )
        .unwrap();
    }

    fn server_endpoints(
        conf: &ServerConfig,
        interface: &InterfaceName,
    ) -> (Option<Endpoint>, Option<Endpoint>) {
        let conn = open_database_connection(interface, conf).unwrap();
        let peer = DatabasePeer::get(&conn, SERVER_PEER_ID).unwrap();
        (
            peer.endpoint.clone(),
            peer.ipv6_external_endpoint().cloned(),
        )
    }

    #[test]
    fn test_init_stores_ipv6_endpoint() {
        let (_dir, conf, interface) = init(Some("[2001:db8::1]:51820"));
        assert_eq!(
            server_endpoints(&conf, &interface),
            (
                Some(endpoint("203.0.113.1:51820")),
                Some(endpoint("[2001:db8::1]:51820"))
            )
        );
    }

    #[test]
    fn test_set_and_unset_ipv6_endpoint() {
        let (_dir, conf, interface) = init(None);
        assert_eq!(server_endpoints(&conf, &interface).1, None);

        for v6 in ["[2001:db8::1]:51820", "[2001:db8::2]:51820"] {
            set(
                &conf,
                &interface,
                SetExternalEndpointOpts {
                    external_endpoint_v6: Some(endpoint(v6)),
                    ..Default::default()
                },
            );
            assert_eq!(
                server_endpoints(&conf, &interface),
                (Some(endpoint("203.0.113.1:51820")), Some(endpoint(v6)))
            );
        }

        set(
            &conf,
            &interface,
            SetExternalEndpointOpts {
                unset_external_endpoint_v6: true,
                ..Default::default()
            },
        );
        assert_eq!(
            server_endpoints(&conf, &interface),
            (Some(endpoint("203.0.113.1:51820")), None)
        );
    }

    #[test]
    fn test_set_primary_endpoint_keeps_ipv6_endpoint() {
        let (_dir, conf, interface) = init(Some("[2001:db8::1]:51820"));

        set(
            &conf,
            &interface,
            SetExternalEndpointOpts {
                external_endpoint: Some(endpoint("198.51.100.1:51820")),
                ..Default::default()
            },
        );
        assert_eq!(
            server_endpoints(&conf, &interface),
            (
                Some(endpoint("198.51.100.1:51820")),
                Some(endpoint("[2001:db8::1]:51820"))
            )
        );
    }

    #[test]
    fn test_ipv6_endpoint_flags_require_ipv6() {
        for (value, valid) in [("[2001:db8::1]:51820", true), ("198.51.100.1:51820", false)] {
            let set_args = ["set", "--external-endpoint-v6", value];
            let init_args = ["new", "--external-endpoint-v6", value];
            assert_eq!(
                SetExternalEndpointOpts::try_parse_from(set_args).is_ok(),
                valid
            );
            assert_eq!(InitializeOpts::try_parse_from(init_args).is_ok(), valid);
        }
    }
}

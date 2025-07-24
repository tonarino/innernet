use clap::{Parser, Subcommand};
use colored::*;
use shared::{
    AddCidrOpts, AddPeerOpts, DeleteCidrOpts, EnableDisablePeerOpts, NetworkOpts, RenameCidrOpts,
    RenamePeerOpts,
};
use std::{env, path::PathBuf};

use innernet_server::{
    add_cidr, add_peer, delete_cidr, enable_or_disable_peer,
    initialize::{self, InitializeOpts},
    rename_cidr, rename_peer, serve, uninstall, ServerConfig,
};
use shared::Interface;

#[derive(Debug, Parser)]
#[command(name = "innernet-server", author, version, about)]
struct Opts {
    #[clap(subcommand)]
    command: Command,

    #[clap(short, long, default_value = "/etc/innernet-server")]
    config_dir: PathBuf,

    #[cfg(not(target_os = "openbsd"))]
    #[clap(short, long, default_value = "/var/lib/innernet-server")]
    data_dir: PathBuf,

    #[cfg(target_os = "openbsd")]
    #[clap(short, long, default_value = "/var/db/innernet-server")]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new network.
    #[clap(alias = "init")]
    New {
        #[clap(flatten)]
        opts: InitializeOpts,
    },

    /// Permanently uninstall a created network, rendering it unusable. Use with care.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Serve the coordinating server for an existing network.
    Serve {
        interface: Interface,

        #[clap(flatten)]
        network: NetworkOpts,
    },

    /// Add a peer to an existing network.
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        args: AddPeerOpts,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Rename an existing peer.
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        args: RenamePeerOpts,
    },

    /// Add a new CIDR to an existing network.
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        args: AddCidrOpts,
    },

    /// Rename an existing CIDR.
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        args: RenameCidrOpts,
    },

    /// Delete a CIDR.
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        args: DeleteCidrOpts,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("RUST_LOG").is_none() {
        // Set some default log settings.
        env::set_var("RUST_LOG", "warn,warp=info,wg_manage_server=info");
    }

    pretty_env_logger::init();
    let opts = Opts::parse();

    if unsafe { libc::getuid() } != 0 && !matches!(opts.command, Command::Completions { .. }) {
        return Err("innernet-server must run as root.".into());
    }

    let conf = ServerConfig::new(opts.config_dir, opts.data_dir);

    match opts.command {
        Command::New { opts } => {
            if let Err(e) = initialize::init_wizard(&conf, opts) {
                eprintln!("{}: {}.", "creation failed".red(), e);
                std::process::exit(1);
            }
        },
        Command::Uninstall { interface, yes } => uninstall(&interface, &conf, opts.network, yes)?,
        Command::Serve {
            interface,
            network: routing,
        } => serve(*interface, &conf, routing).await?,
        Command::AddPeer { interface, args } => add_peer(&interface, &conf, args, opts.network)?,
        Command::RenamePeer { interface, args } => rename_peer(&interface, &conf, args)?,
        Command::DisablePeer { interface, args } => {
            enable_or_disable_peer(&interface, &conf, false, opts.network, args)?
        },
        Command::EnablePeer { interface, args } => {
            enable_or_disable_peer(&interface, &conf, true, opts.network, args)?
        },
        Command::AddCidr { interface, args } => add_cidr(&interface, &conf, args)?,
        Command::RenameCidr { interface, args } => rename_cidr(&interface, &conf, args)?,
        Command::DeleteCidr { interface, args } => delete_cidr(&interface, &conf, args)?,
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}

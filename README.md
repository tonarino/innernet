# innernet

A private network system that uses [WireGuard](https://wireguard.com) under the hood. See the [announcement blog post](https://blog.tonari.no/introducing-innernet) for a longer-winded explanation.

`innernet` is similar in its goals to Slack's [nebula](https://github.com/slackhq/nebula) or [Tailscale](https://tailscale.com/), but takes a bit of a different approach. It aims to take advantage of existing networking concepts like CIDRs and the security properties of WireGuard to turn your computer's basic IP networking into more powerful ACL primitives.

`innernet` is not an official WireGuard project, and WireGuard is a registered trademark of Jason A. Donenfeld.

This has not received an independent security audit, and should be considered experimental software at this early point in its lifetime.

## Usage

### Server Creation

Every `innernet` network needs a coordination server to manage peers and provide endpoint information so peers can contact each other. Create a new one with

```sh
sudo innernet-server new
```

The init wizard will ask you questions about your network and give you some reasonable defaults. It's good to familiarize yourself with [network CIDRs](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) as a lot of innernet's access control is based upon them. As an example, let's say the root CIDR for this network is `10.60.0.0/16`. Server initialization creates a special "infra" CIDR which contains the `innernet` server itself and is reachable from all CIDRs on the network.

Next we'll also create a `humans` CIDR where we can start adding some peers.

```sh
sudo innernet-server add-cidr <interface>
```

For the parent CIDR, you can simply choose your network's root CIDR. The name will be `humans`, and the CIDR will be `10.60.64.0/24` (not a great example unless you only want to support 256 humans, but it works for now...).

By default, peers which exist in this new CIDR will only be able to contact peers in the same CIDR, and the special "infra" CIDR which was created when the server was initialized.

A typical workflow for creating a new network is to create an admin peer from the `innernet-server` CLI, and then continue using that admin peer via the `innernet` client CLI to add any further peers or network CIDRs.

```sh
sudo innernet-server add-peer <interface>
```

Select the `humans` CIDR, and the CLI will automatically suggest the next available IP address. Any name is fine, just answer "yes" when asked if you would like to make the peer an admin. The process of adding a peer results in an invitation file. This file contains just enough information for the new peer to contact the `innernet` server and redeem its invitation. It should be transferred securely to the new peer, and it can only be used once to initialize the peer.

You can run the server with `innernet-server serve <interface>`, or if you're on Linux and want to run it via `systemctl`, run `systemctl enable --now innernet-server@<interface>`. If you're on a home network, don't forget to configure port forwarding to the `Listen Port` you specified when creating the `innernet` server.

### Peer Initialization

Let's assume the invitation file generated in the steps above have been transferred to the machine a network admin will be using.

You can initialize the client with

```sh
sudo inn install /path/to/invitation.toml
```

You can customize the network name if you want to, or leave it at the default. `innernet` will then connect to the `innernet` server via WireGuard, generate a new key pair, and register that pair with the server. The private key in the invitation file can no longer be used.

If everything was successful, the new peer is on the network. You can run things like

```sh
sudo inn list
```

or

```sh
sudo inn list --tree
```

to view the current network and all CIDRs visible to this peer.

Since we created an admin peer, we can also add new peers and CIDRs from this peer via `innernet` instead of having to always run commands on the server.

### Adding Associations between CIDRs

In order for peers from one CIDR to be able to contact peers in another CIDR, those two CIDRs must be "associated" with each other.

With the admin peer we created above, let's add a new CIDR for some theoretical CI servers we have.

```sh
sudo inn add-cidr <interface>
```

The name is `ci-servers` and the CIDR is `10.60.64.0/24`, but for this example it can be anything.

For now, we want peers in the `humans` CIDR to be able to access peers in the `ci-servers` CIDR.

```sh
sudo inn add-association <interface>
```

The CLI will ask you to select the two CIDRs you want to associate. That's all it takes to allow peers in two different CIDRs to communicate!

You can verify the association with

```sh
sudo inn list-associations <interface>
```

and associations can be deleted with

```sh
sudo inn delete-associations <interface>
```

### Enabling/Disabling Peers

For security reasons, IP addresses cannot be re-used by new peers, and therefore peers cannot be deleted. However, they can be disabled. Disabled peers will not show up in the list of peers when fetching the config for an interface.

Disable a peer with

```su
sudo inn disable-peer <interface>
```

Or re-enable a peer with

```su
sudo inn enable-peer <interface>
```

### Specifying a Manual Endpoint

The `innernet` server will try to use the internet endpoint it sees from a peer so other peers can connect to that peer as well. This doesn't always work and you may want to set an endpoint explicitly. To set an endpoint, use

```sh
sudo inn override-endpoint <interface>
```

You can go back to automatic endpoint discovery with

```sh
sudo inn override-endpoint -u <interface>
```

### Setting the Local WireGuard Listen Port

If you want to change the port which WireGuard listens on, use

```sh
sudo inn set-listen-port <interface>
```

or unset the port and use a randomized port with

```sh
sudo innernet set-listen-port -u <interface>
```

## Installation

### Arch

```sh
yay -S innernet
```

### Ubuntu

Fetch the appropriate `.deb` packages from
https://github.com/tonarino/innernet/releases and install with

```sh
sudo apt install ./innernet*.deb
```

### macOS

```sh
./macos/install.sh
```

## Development

### Releases

1. Run `cargo release [--dry-run] [{]minor|major|patch|...]` to automatically bump the crates appropriately.
2. Create a new git tag (ex. `v0.6.0`).
3. Push (with tags) to the repo.

innernet uses GitHub Actions to automatically produce a debian package for the [releases page](https://github.com/tonarino/innernet/releases).

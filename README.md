# innernet

[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/tonarino/innernet/blob/master/LICENSE)

A private network system that uses [WireGuard](https://wireguard.com) under the hood. See the [announcement blog post](https://blog.tonari.no/introducing-innernet) for a longer-winded explanation.

<img src="https://user-images.githubusercontent.com/373823/118917068-09ae7700-b96b-11eb-80f4-6860072d504d.gif" width="600" height="370">

`innernet` is similar in its goals to Slack's [nebula](https://github.com/slackhq/nebula) or [Tailscale](https://tailscale.com/), but takes a bit of a different approach. It aims to take advantage of existing networking concepts like CIDRs and the security properties of WireGuard to turn your computer's basic IP networking into more powerful ACL primitives.

`innernet` is not an official WireGuard project, and WireGuard is a registered trademark of Jason A. Donenfeld.

This has not received an independent security audit, and should be considered experimental software at this early point in its lifetime.

## Usage

### Server Creation

Every `innernet` network needs a coordination server to manage peers and provide endpoint information so peers can directly connect to each other. Create a new one with

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
sudo innernet install /path/to/invitation.toml
```

You can customize the network name if you want to, or leave it at the default. `innernet` will then connect to the `innernet` server via WireGuard, generate a new key pair, and register that pair with the server. The private key in the invitation file can no longer be used.

If everything was successful, the new peer is on the network. You can run things like

```sh
sudo innernet list
```

or

```sh
sudo innernet list --tree
```

to view the current network and all CIDRs visible to this peer.

Since we created an admin peer, we can also add new peers and CIDRs from this peer via `innernet` instead of having to always run commands on the server.

### Adding Associations between CIDRs

In order for peers from one CIDR to be able to contact peers in another CIDR, those two CIDRs must be "associated" with each other.

With the admin peer we created above, let's add a new CIDR for some theoretical CI servers we have.

```sh
sudo innernet add-cidr <interface>
```

The name is `ci-servers` and the CIDR is `10.60.64.0/24`, but for this example it can be anything.

For now, we want peers in the `humans` CIDR to be able to access peers in the `ci-servers` CIDR.

```sh
sudo innernet add-association <interface>
```

The CLI will ask you to select the two CIDRs you want to associate. That's all it takes to allow peers in two different CIDRs to communicate!

You can verify the association with

```sh
sudo innernet list-associations <interface>
```

and associations can be deleted with

```sh
sudo innernet delete-associations <interface>
```

### Enabling/Disabling Peers

For security reasons, IP addresses cannot be re-used by new peers, and therefore peers cannot be deleted. However, they can be disabled. Disabled peers will not show up in the list of peers when fetching the config for an interface.

Disable a peer with

```su
sudo innernet disable-peer <interface>
```

Or re-enable a peer with

```su
sudo innernet enable-peer <interface>
```

### Specifying a Manual Endpoint

The `innernet` server will try to use the internet endpoint it sees from a peer so other peers can connect to that peer as well. This doesn't always work and you may want to set an endpoint explicitly. To set an endpoint, use

```sh
sudo innernet override-endpoint <interface>
```

You can go back to automatic endpoint discovery with

```sh
sudo innernet override-endpoint -u <interface>
```

### Setting the Local WireGuard Listen Port

If you want to change the port which WireGuard listens on, use

```sh
sudo innernet set-listen-port <interface>
```

or unset the port and use a randomized port with

```sh
sudo innernet set-listen-port -u <interface>
```

### Remove Network

To permanently uninstall a created network, use

```sh
sudo innernet-server uninstall <interface>
```

Use with care!

## Security recommendations

If you're running a service on innernet, there are some important security considerations.

### Enable strict Reverse Path Filtering ([RFC 3704](https://tools.ietf.org/html/rfc3704))

Strict RPF prevents packets from _other_ interfaces from having internal source IP addresses. This is _not_ the default on Linux, even though it is the right choice for 99.99% of situations. You can enable it by adding the following to a `/etc/sysctl.d/60-network-security.conf`:

```
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
```

### Bind to the WireGuard device

If possible, to _ensure_ that packets are only ever transmitted over the WireGuard interface, it's recommended that you use `SO_BINDTODEVICE` on Linux or `IP_BOUND_IF` on macOS/BSDs. If you have strict reverse path filtering, though, this is less of a concern.

### IP addresses alone often aren't enough authentication

Even following all the above precautions, rogue applications on a peer's machines could be able to make requests on their behalf unless you add extra layers of authentication to mitigate this CSRF-type vector.

It's recommended that you carefully consider this possibility before deciding that the source IP is sufficient for your authentication needs on a service.

## Installation

innernet has only officially been tested on Linux and MacOS, but we hope to support as many platforms as is feasible!

### Runtime Dependencies

It's assumed that WireGuard is installed on your system, either via the kernel module in Linux 5.6 and later, or via the [`wireguard-go`](https://git.zx2c4.com/wireguard-go/about/) userspace implementation.

[WireGuard Installation Instructions](https://www.wireguard.com/install/)

### Arch Linux

```sh
pacman -S innernet
```

### Debian and Ubuntu

[**@tommie**](https://github.com/tommie) is kindly providing Debian/Ubuntu innernet builds in the https://github.com/tommie/innernet-debian repository.

### Other Linux Distributions

We're looking for volunteers who are able to set up external builds for popular distributions. Please see issue [#203](https://github.com/tonarino/innernet/issues/203).

### macOS

```sh
brew install tonarino/innernet/innernet
```

### Cargo

```sh
# to install innernet:
cargo install --git https://github.com/tonarino/innernet --tag v1.6.1 client

# to install innernet-server:
cargo install --git https://github.com/tonarino/innernet --tag v1.6.1 innernet-server
```

Note that you'll be responsible for updating manually.

## Development

### Cargo build feature for SELinux

If your target system uses SELinux, you will want to enable the 'selinux' feature when building the innernet binary.
This will ensure that innernet maintains the correct selinux context on the /etc/hosts file when adding hosts.  To do so add ```--features selinux``` to the ```cargo build``` options.
The `selinux-devel` package will need to be installed for the correct headers.

### `innernet-server` Build dependencies

- `rustc` / `cargo` (version 1.50.0 or higher)
- `libclang` (see more info at [https://crates.io/crates/clang-sys](https://crates.io/crates/clang-sys))
- `libsqlite3`

Build:

```sh
cargo build --release --bin innernet-server
```

The resulting binary will be located at `./target/release/innernet-server`

### `innernet` Client CLI Build dependencies

- `rustc` / `cargo` (version 1.50.0 or higher)
- `libclang` (see more info at [https://crates.io/crates/clang-sys](https://crates.io/crates/clang-sys))

Build:

```sh
cargo build --release --bin innernet
```

The resulting binary will be located at `./target/release/innernet`

### Testing

You can manually invoke Docker-based tests assuming you have Docker daemon running. If you specify
`--interactive` flag, it allows you to attach to the server and client innernet Docker
containers, so you can test various innernet commands inside a sandboxed environment.

```
docker-tests/build-docker-images.sh
docker-tests/run-docker-tests.sh [--interactive]
```

If you are developing a new feature, please consider adding a new test case to `run-docker-tests.sh` ([example PR](https://github.com/tonarino/innernet/pull/310/files#diff-5d47ea0d379e45f35471e2afa48fdba09d2ca4bcf090e16bb1adccebea080081)).

### Releases

Please run the release script from a Linux machine: generated shell completions depend on available wireguard backends and Mac doesn't support the `kernel` backend. 

1. Fetch and check-out the `main` branch.
2. Run `./release.sh [patch|major|minor|rc]`
3. Push the `main` branch and the created tag to the repo.
4. Publish crates that have `publish = true` to crates.io.

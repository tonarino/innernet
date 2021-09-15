# `wireguard-control`

A high-level control library to get and set configurations for WireGuard interfaces.

It's a heavily-modified fork of [K900's `wgctrl-rs`](https://gitlab.com/K900/wgctrl-rs), and was made for [innernet](https://github.com/tonarino/innernet).

Currently supports:

* Linux kernel WireGuard implementation
* Userspace WireGuard implementations (tested against `wireguard-go` on macOS and Linux)

Versioning is held in lockstep with innernet, although this may change in the future.
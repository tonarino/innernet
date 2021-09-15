# `wireguard-control-sys`

A low-level FFI around the [`embaddable-wg-library`](https://git.zx2c4.com/wireguard-tools/tree/contrib/embeddable-wg-library) WireGuard C library, which in turn communicates with the Linux kernel WireGuard via Netlink.

You *probably* want to use the [`wireguard-control`](https://crates.io/crates/wireguard-control) crate instead.

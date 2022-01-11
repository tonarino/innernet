complete -c innernet-server -n "__fish_use_subcommand" -s c -l config-dir -r
complete -c innernet-server -n "__fish_use_subcommand" -s d -l data-dir -r
complete -c innernet-server -n "__fish_use_subcommand" -l backend -d 'Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability' -r -f -a "{kernel	,userspace	}"
complete -c innernet-server -n "__fish_use_subcommand" -l mtu -d 'Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)' -r
complete -c innernet-server -n "__fish_use_subcommand" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_use_subcommand" -s V -l version -d 'Print version information'
complete -c innernet-server -n "__fish_use_subcommand" -l no-routing -d 'Whether the routing should be done by innernet or is done by an external tool like e.g. babeld'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "new" -d 'Create a new network'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "uninstall" -d 'Permanently uninstall a created network, rendering it unusable. Use with care'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "serve" -d 'Serve the coordinating server for an existing network'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "add-peer" -d 'Add a peer to an existing network'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "rename-peer" -d 'Rename an existing peer'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "add-cidr" -d 'Add a new CIDR to an existing network'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "delete-cidr" -d 'Delete a CIDR'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "completions" -d 'Generate shell completion scripts'
complete -c innernet-server -n "__fish_use_subcommand" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c innernet-server -n "__fish_seen_subcommand_from new" -l network-name -d 'The network name (ex: evilcorp)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from new" -l network-cidr -d 'The network CIDR (ex: 10.42.0.0/16)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from new" -l external-endpoint -d 'This server\'s external endpoint (ex: 100.100.100.100:51820)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from new" -l listen-port -d 'Port to listen on (for the WireGuard interface)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from new" -l auto-external-endpoint -d 'Auto-resolve external endpoint'
complete -c innernet-server -n "__fish_seen_subcommand_from new" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from uninstall" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from serve" -l backend -d 'Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability' -r -f -a "{kernel	,userspace	}"
complete -c innernet-server -n "__fish_seen_subcommand_from serve" -l mtu -d 'Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from serve" -l no-routing -d 'Whether the routing should be done by innernet or is done by an external tool like e.g. babeld'
complete -c innernet-server -n "__fish_seen_subcommand_from serve" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l name -d 'Name of new peer' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l ip -d 'Specify desired IP of new peer (within parent CIDR)' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l cidr -d 'Name of CIDR to add new peer under' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l admin -d 'Make new peer an admin?' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l save-config -d 'Save the config to the given location' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l invite-expires -d 'Invite expiration period (eg. \'30d\', \'7w\', \'2h\', \'60m\', \'1000s\')' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l auto-ip -d 'Auto-assign the peer the first available IP within the CIDR'
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_seen_subcommand_from add-peer" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from rename-peer" -l name -d 'Name of peer to rename' -r
complete -c innernet-server -n "__fish_seen_subcommand_from rename-peer" -l new-name -d 'The new name of the peer' -r
complete -c innernet-server -n "__fish_seen_subcommand_from rename-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_seen_subcommand_from rename-peer" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from add-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-cidr" -l cidr -d 'The CIDR network (eg. \'10.42.5.0/24\')' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-cidr" -l parent -d 'The CIDR parent name' -r
complete -c innernet-server -n "__fish_seen_subcommand_from add-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_seen_subcommand_from add-cidr" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from delete-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet-server -n "__fish_seen_subcommand_from delete-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_seen_subcommand_from delete-cidr" -s h -l help -d 'Print help information'
complete -c innernet-server -n "__fish_seen_subcommand_from completions" -s h -l help -d 'Print help information'

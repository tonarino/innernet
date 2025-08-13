# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_innernet_server_global_optspecs
	string join \n c/config-dir= d/data-dir= no-routing backend= mtu= h/help V/version
end

function __fish_innernet_server_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_innernet_server_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_innernet_server_using_subcommand
	set -l cmd (__fish_innernet_server_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c innernet-server -n "__fish_innernet_server_needs_command" -s c -l config-dir -r -F
complete -c innernet-server -n "__fish_innernet_server_needs_command" -s d -l data-dir -r -F
complete -c innernet-server -n "__fish_innernet_server_needs_command" -l backend -d 'Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability' -r -f -a "kernel\t''
userspace\t''"
complete -c innernet-server -n "__fish_innernet_server_needs_command" -l mtu -d 'Specify the desired MTU for your interface (default: 1280)' -r
complete -c innernet-server -n "__fish_innernet_server_needs_command" -l no-routing -d 'Whether the routing should be done by innernet or is done by an external tool like e.g. babeld'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -s V -l version -d 'Print version'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "new" -d 'Create a new network'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "uninstall" -d 'Permanently uninstall a created network, rendering it unusable. Use with care'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "serve" -d 'Serve the coordinating server for an existing network'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "add-peer" -d 'Add a peer to an existing network'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "disable-peer" -d 'Disable an enabled peer'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "enable-peer" -d 'Enable a disabled peer'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "rename-peer" -d 'Rename an existing peer'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "add-cidr" -d 'Add a new CIDR to an existing network'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "rename-cidr" -d 'Rename an existing CIDR'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "delete-cidr" -d 'Delete a CIDR'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "completions" -d 'Generate shell completion scripts'
complete -c innernet-server -n "__fish_innernet_server_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -l network-name -d 'The network name (ex: evilcorp)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -l network-cidr -d 'The network CIDR (ex: 10.42.0.0/16)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -l external-endpoint -d 'This server\'s external endpoint (ex: 100.100.100.100:51820)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -l listen-port -d 'Port to listen on (for the WireGuard interface)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -l auto-external-endpoint -d 'Auto-resolve external endpoint'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand new" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand uninstall" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand uninstall" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -l backend -d 'Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability' -r -f -a "kernel\t''
userspace\t''"
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -l mtu -d 'Specify the desired MTU for your interface (default: 1280)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -l hosts-path -d 'The path to write hosts to' -r -F
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -l no-routing -d 'Whether the routing should be done by innernet or is done by an external tool like e.g. babeld'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -l no-write-hosts -d 'Don\'t write to any hosts files'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand serve" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l name -d 'Name of new peer' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l ip -d 'Specify desired IP of new peer (within parent CIDR)' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l cidr -d 'Name of CIDR to add new peer under' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l admin -d 'Make new peer an admin?' -r -f -a "true\t''
false\t''"
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l save-config -d 'Save the config to the given location' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l invite-expires -d 'Invite expiration period (eg. \'30d\', \'7w\', \'2h\', \'60m\', \'1000s\')' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l auto-ip -d 'Auto-assign the peer the first available IP within the CIDR'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-peer" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand disable-peer" -l name -d 'Name of peer to enable/disable' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand disable-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand disable-peer" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand enable-peer" -l name -d 'Name of peer to enable/disable' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand enable-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand enable-peer" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-peer" -l name -d 'Name of peer to rename' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-peer" -l new-name -d 'The new name of the peer' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-peer" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-peer" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-cidr" -l cidr -d 'The CIDR network (eg. \'10.42.5.0/24\')' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-cidr" -l parent -d 'The CIDR parent name' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand add-cidr" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-cidr" -l name -d 'Name of CIDR to rename' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-cidr" -l new-name -d 'The new name of the CIDR' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand rename-cidr" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand delete-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet-server -n "__fish_innernet_server_using_subcommand delete-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand delete-cidr" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand completions" -s h -l help -d 'Print help'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "new" -d 'Create a new network'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "uninstall" -d 'Permanently uninstall a created network, rendering it unusable. Use with care'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "serve" -d 'Serve the coordinating server for an existing network'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "add-peer" -d 'Add a peer to an existing network'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "disable-peer" -d 'Disable an enabled peer'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "enable-peer" -d 'Enable a disabled peer'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "rename-peer" -d 'Rename an existing peer'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "add-cidr" -d 'Add a new CIDR to an existing network'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "rename-cidr" -d 'Rename an existing CIDR'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "delete-cidr" -d 'Delete a CIDR'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "completions" -d 'Generate shell completion scripts'
complete -c innernet-server -n "__fish_innernet_server_using_subcommand help; and not __fish_seen_subcommand_from new uninstall serve add-peer disable-peer enable-peer rename-peer add-cidr rename-cidr delete-cidr completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'

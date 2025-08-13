# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_innernet_global_optspecs
	string join \n v/verbose c/config-dir= d/data-dir= no-routing backend= mtu= h/help V/version
end

function __fish_innernet_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_innernet_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_innernet_using_subcommand
	set -l cmd (__fish_innernet_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c innernet -n "__fish_innernet_needs_command" -s c -l config-dir -r -F
complete -c innernet -n "__fish_innernet_needs_command" -s d -l data-dir -r -F
complete -c innernet -n "__fish_innernet_needs_command" -l backend -d 'Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability' -r -f -a "kernel\t''
userspace\t''"
complete -c innernet -n "__fish_innernet_needs_command" -l mtu -d 'Specify the desired MTU for your interface (default: 1280)' -r
complete -c innernet -n "__fish_innernet_needs_command" -s v -l verbose -d 'Verbose output, use -vv for even higher verbositude'
complete -c innernet -n "__fish_innernet_needs_command" -l no-routing -d 'Whether the routing should be done by innernet or is done by an external tool like e.g. babeld'
complete -c innernet -n "__fish_innernet_needs_command" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_needs_command" -s V -l version -d 'Print version'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "install" -d 'Install a new innernet config'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "show" -d 'Enumerate all innernet connections'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "up" -d 'Bring up your local interface, and update it with latest peer list'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "fetch" -d 'Fetch and update your local interface with the latest peer list'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "uninstall" -d 'Uninstall an innernet network'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "down" -d 'Bring down the interface (equivalent to \'wg-quick down <interface>\')'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "add-peer" -d 'Add a new peer'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "rename-peer" -d 'Rename a peer'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "add-cidr" -d 'Add a new CIDR'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "rename-cidr" -d 'Rename a CIDR'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "delete-cidr" -d 'Delete a CIDR'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "list-cidrs" -d 'List CIDRs'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "disable-peer" -d 'Disable an enabled peer'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "enable-peer" -d 'Enable a disabled peer'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "add-association" -d 'Add an association between CIDRs'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "delete-association" -d 'Delete an association between CIDRs'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "list-associations" -d 'List existing assocations between CIDRs'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "set-listen-port" -d 'Set the local listen port'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "override-endpoint" -d 'Override your external endpoint that the server sends to other peers'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "completions" -d 'Generate shell completion scripts'
complete -c innernet -n "__fish_innernet_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c innernet -n "__fish_innernet_using_subcommand install" -l hosts-path -d 'The path to write hosts to' -r -F
complete -c innernet -n "__fish_innernet_using_subcommand install" -l name -d 'Set a specific interface name' -r
complete -c innernet -n "__fish_innernet_using_subcommand install" -l exclude-nat-candidates -d 'Exclude one or more CIDRs from NAT candidate reporting. ex. --exclude-nat-candidates \'0.0.0.0/0\' would report no candidates' -r
complete -c innernet -n "__fish_innernet_using_subcommand install" -l no-write-hosts -d 'Don\'t write to any hosts files'
complete -c innernet -n "__fish_innernet_using_subcommand install" -l default-name -d 'Use the network name inside the invitation as the interface name'
complete -c innernet -n "__fish_innernet_using_subcommand install" -s d -l delete-invite -d 'Delete the invitation after a successful install'
complete -c innernet -n "__fish_innernet_using_subcommand install" -l no-nat-traversal -d 'Don\'t attempt NAT traversal. Note that this still will report candidates unless you also specify to exclude all NAT candidates'
complete -c innernet -n "__fish_innernet_using_subcommand install" -l no-nat-candidates -d 'Don\'t report any candidates to coordinating server. Shorthand for --exclude-nat-candidates \'0.0.0.0/0\''
complete -c innernet -n "__fish_innernet_using_subcommand install" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand show" -s s -l short -d 'One-line peer list'
complete -c innernet -n "__fish_innernet_using_subcommand show" -s t -l tree -d 'Display peers in a tree based on the CIDRs'
complete -c innernet -n "__fish_innernet_using_subcommand show" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand up" -l interval -d 'Keep fetching the latest peer list at the specified interval in seconds. Valid only in daemon mode' -r
complete -c innernet -n "__fish_innernet_using_subcommand up" -l hosts-path -d 'The path to write hosts to' -r -F
complete -c innernet -n "__fish_innernet_using_subcommand up" -l exclude-nat-candidates -d 'Exclude one or more CIDRs from NAT candidate reporting. ex. --exclude-nat-candidates \'0.0.0.0/0\' would report no candidates' -r
complete -c innernet -n "__fish_innernet_using_subcommand up" -s d -l daemon -d 'Enable daemon mode i.e. keep the process running, while fetching the latest peer list periodically'
complete -c innernet -n "__fish_innernet_using_subcommand up" -l no-write-hosts -d 'Don\'t write to any hosts files'
complete -c innernet -n "__fish_innernet_using_subcommand up" -l no-nat-traversal -d 'Don\'t attempt NAT traversal. Note that this still will report candidates unless you also specify to exclude all NAT candidates'
complete -c innernet -n "__fish_innernet_using_subcommand up" -l no-nat-candidates -d 'Don\'t report any candidates to coordinating server. Shorthand for --exclude-nat-candidates \'0.0.0.0/0\''
complete -c innernet -n "__fish_innernet_using_subcommand up" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -l hosts-path -d 'The path to write hosts to' -r -F
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -l exclude-nat-candidates -d 'Exclude one or more CIDRs from NAT candidate reporting. ex. --exclude-nat-candidates \'0.0.0.0/0\' would report no candidates' -r
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -l no-write-hosts -d 'Don\'t write to any hosts files'
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -l no-nat-traversal -d 'Don\'t attempt NAT traversal. Note that this still will report candidates unless you also specify to exclude all NAT candidates'
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -l no-nat-candidates -d 'Don\'t report any candidates to coordinating server. Shorthand for --exclude-nat-candidates \'0.0.0.0/0\''
complete -c innernet -n "__fish_innernet_using_subcommand fetch" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand uninstall" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand uninstall" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand down" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l name -d 'Name of new peer' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l ip -d 'Specify desired IP of new peer (within parent CIDR)' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l cidr -d 'Name of CIDR to add new peer under' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l admin -d 'Make new peer an admin?' -r -f -a "true\t''
false\t''"
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l save-config -d 'Save the config to the given location' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l invite-expires -d 'Invite expiration period (eg. \'30d\', \'7w\', \'2h\', \'60m\', \'1000s\')' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l auto-ip -d 'Auto-assign the peer the first available IP within the CIDR'
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand add-peer" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c innernet -n "__fish_innernet_using_subcommand rename-peer" -l name -d 'Name of peer to rename' -r
complete -c innernet -n "__fish_innernet_using_subcommand rename-peer" -l new-name -d 'The new name of the peer' -r
complete -c innernet -n "__fish_innernet_using_subcommand rename-peer" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand rename-peer" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c innernet -n "__fish_innernet_using_subcommand add-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-cidr" -l cidr -d 'The CIDR network (eg. \'10.42.5.0/24\')' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-cidr" -l parent -d 'The CIDR parent name' -r
complete -c innernet -n "__fish_innernet_using_subcommand add-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand add-cidr" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand rename-cidr" -l name -d 'Name of CIDR to rename' -r
complete -c innernet -n "__fish_innernet_using_subcommand rename-cidr" -l new-name -d 'The new name of the CIDR' -r
complete -c innernet -n "__fish_innernet_using_subcommand rename-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand rename-cidr" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c innernet -n "__fish_innernet_using_subcommand delete-cidr" -l name -d 'The CIDR name (eg. \'engineers\')' -r
complete -c innernet -n "__fish_innernet_using_subcommand delete-cidr" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand delete-cidr" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand list-cidrs" -s t -l tree -d 'Display CIDRs in tree format'
complete -c innernet -n "__fish_innernet_using_subcommand list-cidrs" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand disable-peer" -l name -d 'Name of peer to enable/disable' -r
complete -c innernet -n "__fish_innernet_using_subcommand disable-peer" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand disable-peer" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand enable-peer" -l name -d 'Name of peer to enable/disable' -r
complete -c innernet -n "__fish_innernet_using_subcommand enable-peer" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand enable-peer" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand add-association" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand add-association" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand delete-association" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand delete-association" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand list-associations" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand set-listen-port" -s l -l listen-port -d 'The listen port you\'d like to set for the interface' -r
complete -c innernet -n "__fish_innernet_using_subcommand set-listen-port" -s u -l unset -d 'Unset the local listen port to use a randomized port'
complete -c innernet -n "__fish_innernet_using_subcommand set-listen-port" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand set-listen-port" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand override-endpoint" -s e -l endpoint -d 'The external endpoint that you\'d like the innernet server to broadcast to other peers. The IP address may be unspecified (all zeros), in which case the server will try to resolve it based on its most recent connection. The port will still be used, even if you decide to use an unspecified IP address' -r
complete -c innernet -n "__fish_innernet_using_subcommand override-endpoint" -s u -l unset -d 'Unset an existing override to use the automatic endpoint discovery'
complete -c innernet -n "__fish_innernet_using_subcommand override-endpoint" -l yes -d 'Bypass confirmation'
complete -c innernet -n "__fish_innernet_using_subcommand override-endpoint" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand completions" -s h -l help -d 'Print help'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "install" -d 'Install a new innernet config'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "show" -d 'Enumerate all innernet connections'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "up" -d 'Bring up your local interface, and update it with latest peer list'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "fetch" -d 'Fetch and update your local interface with the latest peer list'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "uninstall" -d 'Uninstall an innernet network'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "down" -d 'Bring down the interface (equivalent to \'wg-quick down <interface>\')'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "add-peer" -d 'Add a new peer'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "rename-peer" -d 'Rename a peer'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "add-cidr" -d 'Add a new CIDR'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "rename-cidr" -d 'Rename a CIDR'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "delete-cidr" -d 'Delete a CIDR'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "list-cidrs" -d 'List CIDRs'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "disable-peer" -d 'Disable an enabled peer'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "enable-peer" -d 'Enable a disabled peer'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "add-association" -d 'Add an association between CIDRs'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "delete-association" -d 'Delete an association between CIDRs'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "list-associations" -d 'List existing assocations between CIDRs'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "set-listen-port" -d 'Set the local listen port'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "override-endpoint" -d 'Override your external endpoint that the server sends to other peers'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "completions" -d 'Generate shell completion scripts'
complete -c innernet -n "__fish_innernet_using_subcommand help; and not __fish_seen_subcommand_from install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer add-association delete-association list-associations set-listen-port override-endpoint completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'

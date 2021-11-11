#compdef innernet

autoload -U is-at-least

_innernet() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]: :(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)]' \
'*-v[Verbose output, use -vv for even higher verbositude]' \
'*--verbose[Verbose output, use -vv for even higher verbositude]' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
":: :_innernet_commands" \
"*::: :->innernet" \
&& ret=0
    case $state in
    (innernet)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-command-$line[1]:"
        case $line[1] in
            (redeem)
_arguments "${_arguments_options[@]}" \
'--hosts-path=[The path to write hosts to]' \
'(--default-name)--name=[Set a specific interface name]' \
'(--hosts-path)--no-write-hosts[Don'\''t write to any hosts files]' \
'--default-name[Use the network name inside the invitation as the interface name]' \
'-d[Delete the invitation after a successful install]' \
'--delete-invite[Delete the invitation after a successful install]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':invite -- Path to the invitation file:_files' \
&& ret=0
;;
(install)
_arguments "${_arguments_options[@]}" \
'--hosts-path=[The path to write hosts to]' \
'(--default-name)--name=[Set a specific interface name]' \
'(--hosts-path)--no-write-hosts[Don'\''t write to any hosts files]' \
'--default-name[Use the network name inside the invitation as the interface name]' \
'-d[Delete the invitation after a successful install]' \
'--delete-invite[Delete the invitation after a successful install]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':invite -- Path to the invitation file:_files' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" \
'-s[One-line peer list]' \
'--short[One-line peer list]' \
'-t[Display peers in a tree based on the CIDRs]' \
'--tree[Display peers in a tree based on the CIDRs]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
'::interface:_files' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" \
'-s[One-line peer list]' \
'--short[One-line peer list]' \
'-t[Display peers in a tree based on the CIDRs]' \
'--tree[Display peers in a tree based on the CIDRs]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
'::interface:_files' \
&& ret=0
;;
(up)
_arguments "${_arguments_options[@]}" \
'--interval=[Keep fetching the latest peer list at the specified interval in seconds. Valid only in daemon mode]' \
'--hosts-path=[The path to write hosts to]' \
'-d[Enable daemon mode i.e. keep the process running, while fetching the latest peer list periodically]' \
'--daemon[Enable daemon mode i.e. keep the process running, while fetching the latest peer list periodically]' \
'(--hosts-path)--no-write-hosts[Don'\''t write to any hosts files]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(fetch)
_arguments "${_arguments_options[@]}" \
'--hosts-path=[The path to write hosts to]' \
'(--hosts-path)--no-write-hosts[Don'\''t write to any hosts files]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(down)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of new peer]' \
'(--auto-ip)--ip=[Specify desired IP of new peer (within parent CIDR)]' \
'--cidr=[Name of CIDR to add new peer under]' \
'--admin=[Make new peer an admin?]' \
'--save-config=[Save the config to the given location]' \
'--invite-expires=[Invite expiration period (eg. '\''30d'\'', '\''7w'\'', '\''2h'\'', '\''60m'\'', '\''1000s'\'')]' \
'--auto-ip[Auto-assign the peer the first available IP within the CIDR]' \
'--yes[Bypass confirmation]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of peer to rename]' \
'--new-name=[The new name of the peer]' \
'--yes[Bypass confirmation]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]' \
'--cidr=[The CIDR network (eg. '\''10.42.5.0/24'\'')]' \
'--parent=[The CIDR parent name]' \
'--yes[Bypass confirmation]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]' \
'--yes[Bypass confirmation]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(list-cidrs)
_arguments "${_arguments_options[@]}" \
'-t[Display CIDRs in tree format]' \
'--tree[Display CIDRs in tree format]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(disable-peer)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(enable-peer)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(add-association)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
'::cidr1 -- The first cidr to associate:_files' \
'::cidr2 -- The second cidr to associate:_files' \
&& ret=0
;;
(delete-association)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(list-associations)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(set-listen-port)
_arguments "${_arguments_options[@]}" \
'-u[Unset the local listen port to use a randomized port]' \
'--unset[Unset the local listen port to use a randomized port]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(override-endpoint)
_arguments "${_arguments_options[@]}" \
'-u[Unset an existing override to use the automatic endpoint discovery]' \
'--unset[Unset an existing override to use the automatic endpoint discovery]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':interface:_files' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
':shell:(zsh bash fish powershell elvish)' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
&& ret=0
;;
        esac
    ;;
esac
}

(( $+functions[_innernet_commands] )) ||
_innernet_commands() {
    local commands; commands=(
        "install:Install a new innernet config" \
"show:Enumerate all innernet connections" \
"up:Bring up your local interface, and update it with latest peer list" \
"fetch:Fetch and update your local interface with the latest peer list" \
"uninstall:Uninstall an innernet network" \
"down:Bring down the interface (equivalent to 'wg-quick down <interface>')" \
"add-peer:Add a new peer" \
"rename-peer:Rename a peer" \
"add-cidr:Add a new CIDR" \
"delete-cidr:Delete a CIDR" \
"list-cidrs:List CIDRs" \
"disable-peer:Disable an enabled peer" \
"enable-peer:Enable a disabled peer" \
"add-association:Add an association between CIDRs" \
"delete-association:Delete an association between CIDRs" \
"list-associations:List existing assocations between CIDRs" \
"set-listen-port:Set the local listen port" \
"override-endpoint:Override your external endpoint that the server sends to other peers" \
"completions:Generate shell completion scripts" \
"help:Prints this message or the help of the given subcommand(s)" \
    )
    _describe -t commands 'innernet commands' commands "$@"
}
(( $+functions[_innernet__add-association_commands] )) ||
_innernet__add-association_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet add-association commands' commands "$@"
}
(( $+functions[_innernet__add-cidr_commands] )) ||
_innernet__add-cidr_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet add-cidr commands' commands "$@"
}
(( $+functions[_innernet__add-peer_commands] )) ||
_innernet__add-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet add-peer commands' commands "$@"
}
(( $+functions[_innernet__completions_commands] )) ||
_innernet__completions_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet completions commands' commands "$@"
}
(( $+functions[_innernet__delete-association_commands] )) ||
_innernet__delete-association_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet delete-association commands' commands "$@"
}
(( $+functions[_innernet__delete-cidr_commands] )) ||
_innernet__delete-cidr_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet delete-cidr commands' commands "$@"
}
(( $+functions[_innernet__disable-peer_commands] )) ||
_innernet__disable-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet disable-peer commands' commands "$@"
}
(( $+functions[_innernet__down_commands] )) ||
_innernet__down_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet down commands' commands "$@"
}
(( $+functions[_innernet__enable-peer_commands] )) ||
_innernet__enable-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet enable-peer commands' commands "$@"
}
(( $+functions[_innernet__fetch_commands] )) ||
_innernet__fetch_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet fetch commands' commands "$@"
}
(( $+functions[_innernet__help_commands] )) ||
_innernet__help_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet help commands' commands "$@"
}
(( $+functions[_innernet__install_commands] )) ||
_innernet__install_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet install commands' commands "$@"
}
(( $+functions[_innernet__list_commands] )) ||
_innernet__list_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet list commands' commands "$@"
}
(( $+functions[_list_commands] )) ||
_list_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'list commands' commands "$@"
}
(( $+functions[_innernet__list-associations_commands] )) ||
_innernet__list-associations_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet list-associations commands' commands "$@"
}
(( $+functions[_innernet__list-cidrs_commands] )) ||
_innernet__list-cidrs_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet list-cidrs commands' commands "$@"
}
(( $+functions[_innernet__override-endpoint_commands] )) ||
_innernet__override-endpoint_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet override-endpoint commands' commands "$@"
}
(( $+functions[_innernet__redeem_commands] )) ||
_innernet__redeem_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet redeem commands' commands "$@"
}
(( $+functions[_redeem_commands] )) ||
_redeem_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'redeem commands' commands "$@"
}
(( $+functions[_innernet__rename-peer_commands] )) ||
_innernet__rename-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet rename-peer commands' commands "$@"
}
(( $+functions[_innernet__set-listen-port_commands] )) ||
_innernet__set-listen-port_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet set-listen-port commands' commands "$@"
}
(( $+functions[_innernet__show_commands] )) ||
_innernet__show_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet show commands' commands "$@"
}
(( $+functions[_innernet__uninstall_commands] )) ||
_innernet__uninstall_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet uninstall commands' commands "$@"
}
(( $+functions[_innernet__up_commands] )) ||
_innernet__up_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet up commands' commands "$@"
}

_innernet "$@"
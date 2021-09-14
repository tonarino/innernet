#compdef innernet-server

autoload -U is-at-least

_innernet-server() {
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
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]: :(userspace)' \
'--mtu=[Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)]' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
":: :_innernet-server_commands" \
"*::: :->innernet-server" \
&& ret=0
    case $state in
    (innernet-server)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-server-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" \
'--network-name=[The network name (ex: evilcorp)]' \
'--network-cidr=[The network CIDR (ex: 10.42.0.0/16)]' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex: 100.100.100.100:51820)]' \
'--listen-port=[Port to listen on (for the WireGuard interface)]' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
&& ret=0
;;
(init)
_arguments "${_arguments_options[@]}" \
'--network-name=[The network name (ex: evilcorp)]' \
'--network-cidr=[The network CIDR (ex: 10.42.0.0/16)]' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex: 100.100.100.100:51820)]' \
'--listen-port=[Port to listen on (for the WireGuard interface)]' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
&& ret=0
;;
(new)
_arguments "${_arguments_options[@]}" \
'--network-name=[The network name (ex: evilcorp)]' \
'--network-cidr=[The network CIDR (ex: 10.42.0.0/16)]' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex: 100.100.100.100:51820)]' \
'--listen-port=[Port to listen on (for the WireGuard interface)]' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Prints help information]' \
'--help[Prints help information]' \
'-V[Prints version information]' \
'--version[Prints version information]' \
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
(serve)
_arguments "${_arguments_options[@]}" \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]: :(userspace)' \
'--mtu=[Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)]' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
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
'--invite-expires=[Invite expiration period (eg. "30d", "7w", "2h", "60m", "1000s")]' \
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
'--name=[The CIDR name (eg. "engineers")]' \
'--cidr=[The CIDR network (eg. "10.42.5.0/24")]' \
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
'--name=[The CIDR name (eg. "engineers")]' \
'--yes[Bypass confirmation]' \
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

(( $+functions[_innernet-server_commands] )) ||
_innernet-server_commands() {
    local commands; commands=(
        "new:Create a new network" \
"uninstall:Permanently uninstall a created network, rendering it unusable. Use with care" \
"serve:Serve the coordinating server for an existing network" \
"add-peer:Add a peer to an existing network" \
"rename-peer:Rename an existing peer" \
"add-cidr:Add a new CIDR to an existing network" \
"delete-cidr:Delete a CIDR" \
"completions:Generate shell completion scripts" \
"help:Prints this message or the help of the given subcommand(s)" \
    )
    _describe -t commands 'innernet-server commands' commands "$@"
}
(( $+functions[_innernet-server__add-cidr_commands] )) ||
_innernet-server__add-cidr_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server add-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__add-peer_commands] )) ||
_innernet-server__add-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__completions_commands] )) ||
_innernet-server__completions_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server completions commands' commands "$@"
}
(( $+functions[_innernet-server__delete-cidr_commands] )) ||
_innernet-server__delete-cidr_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__help_commands] )) ||
_innernet-server__help_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server help commands' commands "$@"
}
(( $+functions[_init_commands] )) ||
_init_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'init commands' commands "$@"
}
(( $+functions[_innernet-server__init_commands] )) ||
_innernet-server__init_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server init commands' commands "$@"
}
(( $+functions[_innernet-server__new_commands] )) ||
_innernet-server__new_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server new commands' commands "$@"
}
(( $+functions[_innernet-server__rename-peer_commands] )) ||
_innernet-server__rename-peer_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__serve_commands] )) ||
_innernet-server__serve_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server serve commands' commands "$@"
}
(( $+functions[_innernet-server__uninstall_commands] )) ||
_innernet-server__uninstall_commands() {
    local commands; commands=(
        
    )
    _describe -t commands 'innernet-server uninstall commands' commands "$@"
}

_innernet-server "$@"
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
'-c+[]:CONFIG_DIR: ' \
'--config-dir=[]:CONFIG_DIR: ' \
'-d+[]:DATA_DIR: ' \
'--data-dir=[]:DATA_DIR: ' \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)]:MTU: ' \
'-h[Print help information]' \
'--help[Print help information]' \
'-V[Print version information]' \
'--version[Print version information]' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
":: :_innernet-server_commands" \
"*::: :->innernet-server" \
&& ret=0
    case $state in
    (innernet-server)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-server-command-$line[1]:"
        case $line[1] in
            (new)
_arguments "${_arguments_options[@]}" \
'--network-name=[The network name (ex: evilcorp)]:NETWORK_NAME: ' \
'--network-cidr=[The network CIDR (ex: 10.42.0.0/16)]:NETWORK_CIDR: ' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex: 100.100.100.100:51820)]:EXTERNAL_ENDPOINT: ' \
'--listen-port=[Port to listen on (for the WireGuard interface)]:LISTEN_PORT: ' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Print help information]' \
'--help[Print help information]' \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(serve)
_arguments "${_arguments_options[@]}" \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6)]:MTU: ' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of new peer]:NAME: ' \
'(--auto-ip)--ip=[Specify desired IP of new peer (within parent CIDR)]:IP: ' \
'--cidr=[Name of CIDR to add new peer under]:CIDR: ' \
'--admin=[Make new peer an admin?]:ADMIN: ' \
'--save-config=[Save the config to the given location]:SAVE_CONFIG: ' \
'--invite-expires=[Invite expiration period (eg. '\''30d'\'', '\''7w'\'', '\''2h'\'', '\''60m'\'', '\''1000s'\'')]:INVITE_EXPIRES: ' \
'--auto-ip[Auto-assign the peer the first available IP within the CIDR]' \
'--yes[Bypass confirmation]' \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of peer to rename]:NAME: ' \
'--new-name=[The new name of the peer]:NEW_NAME: ' \
'--yes[Bypass confirmation]' \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME: ' \
'--cidr=[The CIDR network (eg. '\''10.42.5.0/24'\'')]:CIDR: ' \
'--parent=[The CIDR parent name]:PARENT: ' \
'--yes[Bypass confirmation]' \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME: ' \
'--yes[Bypass confirmation]' \
'-h[Print help information]' \
'--help[Print help information]' \
':interface:' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" \
'-h[Print help information]' \
'--help[Print help information]' \
':shell:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
        esac
    ;;
esac
}

(( $+functions[_innernet-server_commands] )) ||
_innernet-server_commands() {
    local commands; commands=(
'new:Create a new network' \
'uninstall:Permanently uninstall a created network, rendering it unusable. Use with care' \
'serve:Serve the coordinating server for an existing network' \
'add-peer:Add a peer to an existing network' \
'rename-peer:Rename an existing peer' \
'add-cidr:Add a new CIDR to an existing network' \
'delete-cidr:Delete a CIDR' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'innernet-server commands' commands "$@"
}
(( $+functions[_innernet-server__add-cidr_commands] )) ||
_innernet-server__add-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__add-peer_commands] )) ||
_innernet-server__add-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__completions_commands] )) ||
_innernet-server__completions_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server completions commands' commands "$@"
}
(( $+functions[_innernet-server__delete-cidr_commands] )) ||
_innernet-server__delete-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__help_commands] )) ||
_innernet-server__help_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help commands' commands "$@"
}
(( $+functions[_innernet-server__new_commands] )) ||
_innernet-server__new_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server new commands' commands "$@"
}
(( $+functions[_innernet-server__rename-peer_commands] )) ||
_innernet-server__rename-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__serve_commands] )) ||
_innernet-server__serve_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server serve commands' commands "$@"
}
(( $+functions[_innernet-server__uninstall_commands] )) ||
_innernet-server__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server uninstall commands' commands "$@"
}

_innernet-server "$@"
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
'-c+[]:CONFIG_DIR:_files' \
'--config-dir=[]:CONFIG_DIR:_files' \
'-d+[]:DATA_DIR:_files' \
'--data-dir=[]:DATA_DIR:_files' \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default\: 1280)]:MTU: ' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
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
'--network-name=[The network name (ex\: evilcorp)]:NETWORK_NAME: ' \
'--network-cidr=[The network CIDR (ex\: 10.42.0.0/16)]:NETWORK_CIDR: ' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex\: 100.100.100.100\:51820)]:EXTERNAL_ENDPOINT: ' \
'--listen-port=[Port to listen on (for the WireGuard interface)]:LISTEN_PORT: ' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(serve)
_arguments "${_arguments_options[@]}" \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default\: 1280)]:MTU: ' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of new peer]:NAME: ' \
'(--auto-ip)--ip=[Specify desired IP of new peer (within parent CIDR)]:IP: ' \
'--cidr=[Name of CIDR to add new peer under]:CIDR: ' \
'--admin=[Make new peer an admin?]:ADMIN:(true false)' \
'--save-config=[Save the config to the given location]:SAVE_CONFIG: ' \
'--invite-expires=[Invite expiration period (eg. '\''30d'\'', '\''7w'\'', '\''2h'\'', '\''60m'\'', '\''1000s'\'')]:INVITE_EXPIRES: ' \
'--auto-ip[Auto-assign the peer the first available IP within the CIDR]' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(disable-peer)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(enable-peer)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" \
'--name=[Name of peer to rename]:NAME: ' \
'--new-name=[The new name of the peer]:NEW_NAME: ' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME: ' \
'--cidr=[The CIDR network (eg. '\''10.42.5.0/24'\'')]:CIDR: ' \
'--parent=[The CIDR parent name]:PARENT: ' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME: ' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':shell:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
":: :_innernet-server__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-server-help-command-$line[1]:"
        case $line[1] in
            (new)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(serve)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(disable-peer)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(enable-peer)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
        esac
    ;;
esac
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
'disable-peer:Disable an enabled peer' \
'enable-peer:Enable a disabled peer' \
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
(( $+functions[_innernet-server__help__add-cidr_commands] )) ||
_innernet-server__help__add-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help add-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__add-peer_commands] )) ||
_innernet-server__add-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__help__add-peer_commands] )) ||
_innernet-server__help__add-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__completions_commands] )) ||
_innernet-server__completions_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server completions commands' commands "$@"
}
(( $+functions[_innernet-server__help__completions_commands] )) ||
_innernet-server__help__completions_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help completions commands' commands "$@"
}
(( $+functions[_innernet-server__delete-cidr_commands] )) ||
_innernet-server__delete-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__help__delete-cidr_commands] )) ||
_innernet-server__help__delete-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__disable-peer_commands] )) ||
_innernet-server__disable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server disable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__help__disable-peer_commands] )) ||
_innernet-server__help__disable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help disable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__enable-peer_commands] )) ||
_innernet-server__enable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server enable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__help__enable-peer_commands] )) ||
_innernet-server__help__enable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help enable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__help_commands] )) ||
_innernet-server__help_commands() {
    local commands; commands=(
'new:Create a new network' \
'uninstall:Permanently uninstall a created network, rendering it unusable. Use with care' \
'serve:Serve the coordinating server for an existing network' \
'add-peer:Add a peer to an existing network' \
'disable-peer:Disable an enabled peer' \
'enable-peer:Enable a disabled peer' \
'rename-peer:Rename an existing peer' \
'add-cidr:Add a new CIDR to an existing network' \
'delete-cidr:Delete a CIDR' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'innernet-server help commands' commands "$@"
}
(( $+functions[_innernet-server__help__help_commands] )) ||
_innernet-server__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help help commands' commands "$@"
}
(( $+functions[_innernet-server__help__new_commands] )) ||
_innernet-server__help__new_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help new commands' commands "$@"
}
(( $+functions[_innernet-server__new_commands] )) ||
_innernet-server__new_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server new commands' commands "$@"
}
(( $+functions[_innernet-server__help__rename-peer_commands] )) ||
_innernet-server__help__rename-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__rename-peer_commands] )) ||
_innernet-server__rename-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__help__serve_commands] )) ||
_innernet-server__help__serve_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help serve commands' commands "$@"
}
(( $+functions[_innernet-server__serve_commands] )) ||
_innernet-server__serve_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server serve commands' commands "$@"
}
(( $+functions[_innernet-server__help__uninstall_commands] )) ||
_innernet-server__help__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help uninstall commands' commands "$@"
}
(( $+functions[_innernet-server__uninstall_commands] )) ||
_innernet-server__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server uninstall commands' commands "$@"
}

if [ "$funcstack[1]" = "_innernet-server" ]; then
    _innernet-server "$@"
else
    compdef _innernet-server innernet-server
fi

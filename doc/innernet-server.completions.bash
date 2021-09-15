_innernet-server() {
    local i cur prev opts cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${i}" in
            innernet-server)
                cmd="innernet-server"
                ;;
            
            add-cidr)
                cmd+="__add__cidr"
                ;;
            add-peer)
                cmd+="__add__peer"
                ;;
            completions)
                cmd+="__completions"
                ;;
            delete-cidr)
                cmd+="__delete__cidr"
                ;;
            help)
                cmd+="__help"
                ;;
            init)
                cmd+="__init"
                ;;
            new)
                cmd+="__new"
                ;;
            rename-peer)
                cmd+="__rename__peer"
                ;;
            serve)
                cmd+="__serve"
                ;;
            uninstall)
                cmd+="__uninstall"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        innernet-server)
            opts=" -h -V  --no-routing --help --version --backend --mtu   new uninstall serve add-peer rename-peer add-cidr delete-cidr completions help  init init"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --backend)
                    COMPREPLY=($(compgen -W "kernel userspace" -- "${cur}"))
                    return 0
                    ;;
                --mtu)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        
        innernet__server__add__cidr)
            opts=" -h -V  --yes --help --version --name --cidr --parent  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__add__peer)
            opts=" -h -V  --auto-ip --yes --help --version --name --ip --cidr --admin --save-config --invite-expires  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --admin)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --save-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --invite-expires)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__completions)
            opts=" -h -V  --help --version  <shell> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__delete__cidr)
            opts=" -h -V  --yes --help --version --name  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__help)
            opts=" -h -V  --help --version  "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__init)
            opts=" -h -V  --auto-external-endpoint --help --version --network-name --network-cidr --external-endpoint --listen-port  "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --network-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --network-cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --external-endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --listen-port)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__new)
            opts=" -h -V  --auto-external-endpoint --help --version --network-name --network-cidr --external-endpoint --listen-port  "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --network-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --network-cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --external-endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --listen-port)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__rename__peer)
            opts=" -h -V  --yes --help --version --name --new-name  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__serve)
            opts=" -h -V  --no-routing --help --version --backend --mtu  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --backend)
                    COMPREPLY=($(compgen -W "kernel userspace" -- "${cur}"))
                    return 0
                    ;;
                --mtu)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__server__uninstall)
            opts=" -h -V  --help --version  <interface> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

complete -F _innernet-server -o bashdefault -o default innernet-server

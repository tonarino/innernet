#[cfg(target_os = "linux")]
mod linux {
    use netlink_packet_core::{
        NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
        NETLINK_HEADER_LEN, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
    };
    use netlink_packet_generic::{
        constants::GENL_HDRLEN,
        ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
        GenlFamily, GenlHeader, GenlMessage,
    };
    use netlink_packet_route::RtnlMessage;
    use netlink_packet_utils::{Emitable, ParseableParametrized};
    use netlink_sys::{constants::NETLINK_GENERIC, protocols::NETLINK_ROUTE, Socket};
    use nix::unistd::{sysconf, SysconfVar};
    use once_cell::sync::OnceCell;
    use std::{fmt::Debug, io};

    macro_rules! get_nla_value {
        ($nlas:expr, $e:ident, $v:ident) => {
            $nlas.iter().find_map(|attr| match attr {
                $e::$v(value) => Some(value),
                _ => None,
            })
        };
    }

    pub fn max_netlink_buffer_length() -> usize {
        static LENGTH: OnceCell<usize> = OnceCell::new();
        *LENGTH.get_or_init(|| {
            // https://www.kernel.org/doc/html/v6.2/userspace-api/netlink/intro.html#buffer-sizing
            // "Netlink expects that the user buffer will be at least 8kB or a page
            // size of the CPU architecture, whichever is bigger."
            const MIN_NELINK_BUFFER_LENGTH: usize = 8 * 1024;
            // Note that sysconf only returns Err / Ok(None) when the parameter is
            // invalid, unsupported on the current OS, or an unset limit. PAGE_SIZE
            // is *required* to be supported and is not considered a limit, so this
            // should never fail unless something has gone massively wrong.
            let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;
            std::cmp::max(MIN_NELINK_BUFFER_LENGTH, page_size)
        })
    }

    pub fn max_genl_payload_length() -> usize {
        max_netlink_buffer_length() - NETLINK_HEADER_LEN - GENL_HDRLEN
    }

    pub fn netlink_request_genl<F>(
        mut message: GenlMessage<F>,
        flags: Option<u16>,
    ) -> Result<Vec<NetlinkMessage<GenlMessage<F>>>, io::Error>
    where
        F: GenlFamily + Clone + Debug + Eq + Emitable + ParseableParametrized<[u8], GenlHeader>,
        GenlMessage<F>: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
    {
        if message.family_id() == 0 {
            let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
                cmd: GenlCtrlCmd::GetFamily,
                nlas: vec![GenlCtrlAttrs::FamilyName(F::family_name().to_string())],
            });
            let responses =
                netlink_request_genl::<GenlCtrl>(genlmsg, Some(NLM_F_REQUEST | NLM_F_ACK))?;

            match responses.get(0) {
                Some(NetlinkMessage {
                    payload:
                        NetlinkPayload::InnerMessage(GenlMessage {
                            payload: GenlCtrl { nlas, .. },
                            ..
                        }),
                    ..
                }) => {
                    let family_id = get_nla_value!(nlas, GenlCtrlAttrs, FamilyId)
                        .ok_or_else(|| io::ErrorKind::NotFound)?;
                    message.set_resolved_family_id(*family_id);
                },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected netlink payload",
                    ))
                },
            };
        }
        netlink_request(message, flags, NETLINK_GENERIC)
    }

    pub fn netlink_request_rtnl(
        message: RtnlMessage,
        flags: Option<u16>,
    ) -> Result<Vec<NetlinkMessage<RtnlMessage>>, io::Error> {
        netlink_request(message, flags, NETLINK_ROUTE)
    }

    pub fn netlink_request<I>(
        message: I,
        flags: Option<u16>,
        socket: isize,
    ) -> Result<Vec<NetlinkMessage<I>>, io::Error>
    where
        NetlinkPayload<I>: From<I>,
        I: Clone + Debug + Eq + Emitable + NetlinkSerializable + NetlinkDeserializable,
    {
        let mut req = NetlinkMessage::from(message);

        let max_buffer_len = max_netlink_buffer_length();
        if req.buffer_len() > max_buffer_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Serialized netlink packet ({} bytes) larger than maximum size {}: {:?}",
                    req.buffer_len(),
                    max_buffer_len,
                    req
                ),
            ));
        }

        req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
        req.finalize();
        let mut buf = vec![0; max_buffer_len];
        req.serialize(&mut buf);
        let len = req.buffer_len();

        let socket = Socket::new(socket)?;
        let kernel_addr = netlink_sys::SocketAddr::new(0, 0);
        socket.connect(&kernel_addr)?;
        let n_sent = socket.send(&buf[..len], 0)?;
        if n_sent != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to send netlink request",
            ));
        }

        let mut responses = vec![];
        loop {
            let n_received = socket.recv(&mut &mut buf[..], 0)?;
            let mut offset = 0;
            loop {
                let bytes = &buf[offset..];
                let response = NetlinkMessage::<I>::deserialize(bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                match response.payload {
                    // We've parsed all parts of the response and can leave the loop.
                    NetlinkPayload::Done(_) => return Ok(responses),
                    NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.into()),
                    _ => {},
                }
                responses.push(response.clone());
                offset += response.header.length as usize;
                if offset == n_received || response.header.length == 0 {
                    // We've fully parsed the datagram, but there may be further datagrams
                    // with additional netlink response parts.
                    break;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    max_genl_payload_length, max_netlink_buffer_length, netlink_request, netlink_request_genl,
    netlink_request_rtnl,
};

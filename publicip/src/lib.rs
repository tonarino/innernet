//! Get your public IP address(es) as fast as possible, with no dependencies.
//!
//! Currently uses Cloudflare's DNS as it's the simplest, but that could change
//! in the future.

use std::{
    fs::File,
    io::{Cursor, Error, ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err(Error::new(ErrorKind::InvalidInput, $msg.to_string()));
        }
    };
}

const CLASS_IN: u16 = 0x0001;
const TYPE_A: u16 = 0x0001;
const TYPE_AAAA: u16 = 0x001C;

// Reference: https://www.quad9.net/service/service-addresses-and-features
static QNAME: &[&str] = &["whatismyip", "on", "quad9", "net"];
const IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
const IPV6_ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe);

pub enum Preference {
    Ipv4,
    Ipv6,
}

pub fn get_both() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let v4 = Request::start(IPV4_ADDRESS.into());
    let v6 = Request::start(IPV6_ADDRESS.into());
    (
        v4.and_then(Request::read_response).map(Ipv4Addr::from).ok(),
        v6.and_then(Request::read_response).map(Ipv6Addr::from).ok(),
    )
}

pub fn get_any(preference: Preference) -> Option<IpAddr> {
    let (v4, v6) = get_both();
    let (v4, v6) = (v4.map(IpAddr::from), v6.map(IpAddr::from));
    match preference {
        Preference::Ipv4 => v4.or(v6),
        Preference::Ipv6 => v6.or(v4),
    }
}

struct Request {
    socket: UdpSocket,
    id: [u8; 2],
    buf: [u8; 1500],
    record_type: u16,
}

impl Request {
    fn start(resolver_ip: IpAddr) -> Result<Self, Error> {
        let (addr, record_type) = if resolver_ip.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED.into(), TYPE_A)
        } else {
            (Ipv6Addr::UNSPECIFIED.into(), TYPE_AAAA)
        };
        let socket = UdpSocket::bind(SocketAddr::new(addr, 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let endpoint = SocketAddr::new(resolver_ip, 53);

        let id = get_id()?;
        let mut buf = [0u8; 1500];
        let mut cursor = Cursor::new(&mut buf[..]);
        cursor.write_all(&id)?;
        cursor.write_all(&0x0100u16.to_be_bytes())?; // Request type (query, in this case)
        cursor.write_all(&0x0001u16.to_be_bytes())?; // Number of queries
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of responses
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of name server records
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of additional records
        for atom in QNAME {
            // Write the length of this atom followed by the string itself
            cursor.write_all(&[atom.len() as u8])?;
            cursor.write_all(atom.as_bytes())?;
        }
        // Finish the qname with a terminating byte (0-length atom).
        cursor.write_all(&[0x00])?;
        cursor.write_all(&record_type.to_be_bytes())?;
        cursor.write_all(&CLASS_IN.to_be_bytes())?;

        let len = cursor.position() as usize;
        socket.connect(endpoint)?;
        socket.send(&buf[..len])?;

        Ok(Self {
            socket,
            id,
            buf,
            record_type,
        })
    }

    fn read_response<const N: usize>(mut self) -> Result<[u8; N], Error> {
        let len = self.socket.recv(&mut self.buf)?;
        ensure!(self.buf[..2] == self.id, "question/answer IDs don't match");
        let response = &self.buf[..len];
        let mut buf = Cursor::new(response);
        let _id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        ensure!(flags & 0x8000 != 0, "not a response");
        ensure!(flags & 0x000f == 0, "non-zero DNS error code");

        let qd = buf.read_u16()?;
        ensure!(qd <= 1, "unexpected number of questions");
        ensure!(buf.read_u16()? == 1, "unexpected number of answers");
        ensure!(buf.read_u16()? == 0, "unexpected NS value");
        ensure!(buf.read_u16()? == 0, "unexpected AR value"); // "Additional Records"

        // Skip past the query section, don't care.
        if qd != 0 {
            loop {
                let len = buf.read_u8()?;
                if len == 0 {
                    break;
                }
                buf.set_position(buf.position() + len as u64);
            }
            // Skip type and class information as well.
            buf.set_position(buf.position() + 4);
        }

        let qname_len = buf.read_u16()?;
        // Ignore if it's a pointer, ignore if it's a normal QNAME...
        if qname_len & 0xc000 != 0xc000 {
            buf.set_position(buf.position() + qname_len as u64);
        }
        ensure!(
            buf.read_u16()? == self.record_type,
            "answer is not expected type"
        );
        ensure!(buf.read_u16()? == CLASS_IN, "answer is not IN class");
        buf.set_position(buf.position() + 4); // Ignore TTL

        let mut output = [0u8; N];
        let data_len = buf.read_u16()? as usize;
        let start = buf.position() as usize;
        ensure!(data_len == N, "unexpected record data length");
        output.copy_from_slice(&response[start..(start + data_len)]);
        Ok(output)
    }
}

/// DNS wants a random-ish ID to be generated per request.
fn get_id() -> Result<[u8; 2], Error> {
    let mut id = [0u8; 2];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    Ok(id)
}

trait ReadExt {
    fn read_u16(&mut self) -> Result<u16, std::io::Error>;
    fn read_u8(&mut self) -> Result<u8, std::io::Error>;
}

impl ReadExt for Cursor<&[u8]> {
    fn read_u16(&mut self) -> Result<u16, std::io::Error> {
        let mut u16_buf = [0; 2];
        self.read_exact(&mut u16_buf)?;
        Ok(u16::from_be_bytes(u16_buf))
    }

    fn read_u8(&mut self) -> Result<u8, std::io::Error> {
        let mut u8_buf = [0];
        self.read_exact(&mut u8_buf)?;
        Ok(u8_buf[0])
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::*;

    #[test]
    #[ignore]
    fn it_works() -> Result<(), Error> {
        let now = Instant::now();
        let (v4, v6) = get_both();
        println!("Done in {}ms", now.elapsed().as_millis());
        println!("v4: {v4:?}, v6: {v6:?}");
        assert!(v4.is_some() || v6.is_some());
        Ok(())
    }
}

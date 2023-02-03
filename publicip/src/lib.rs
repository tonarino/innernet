//! Get your public IP address(es) as fast as possible, with no dependencies.
//!
//! Currently uses Cloudflare's DNS as it's the simplest, but that could change
//! in the future.

use std::{
    fs::File,
    io::{Cursor, Error, ErrorKind, Read, Write},
    marker::PhantomData,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str::FromStr,
    time::Duration,
};

macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err(Error::new(ErrorKind::InvalidInput, $msg.to_string()));
        }
    };
}

const TYPE_TXT: u16 = 0x0010; // TXT-type requests (could also be A, AAAA, etc.)
const CLASS_CH: u16 = 0x0003; // Because we are in the chaos realm.

static CLOUDFLARE_QNAME: &[&str] = &["whoami", "cloudflare"];
const CLOUDFLARE_IPV4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const CLOUDFLARE_IPV6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

pub enum Preference {
    Ipv4,
    Ipv6,
}

pub fn get_both() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let ipv4 = Request::start(CLOUDFLARE_IPV4).ok();
    let ipv6 = Request::start(CLOUDFLARE_IPV6).ok();
    (
        ipv4.and_then(|req| req.read_response().ok()),
        ipv6.and_then(|req| req.read_response().ok()),
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

struct Request<T> {
    socket: UdpSocket,
    id: [u8; 2],
    buf: [u8; 1500],
    _ip_type: PhantomData<T>,
}

impl<T: Into<IpAddr> + FromStr<Err = AddrParseError>> Request<T> {
    fn start(resolver: T) -> Result<Self, Error> {
        let socket = UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let endpoint = SocketAddr::new(resolver.into(), 53);

        let id = get_id()?;
        let mut buf = [0u8; 1500];
        let mut cursor = Cursor::new(&mut buf[..]);
        cursor.write_all(&id)?;
        cursor.write_all(&0x0100u16.to_be_bytes())?; // Request type (query, in this case)
        cursor.write_all(&0x0001u16.to_be_bytes())?; // Number of queries
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of responses
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of name server records
        cursor.write_all(&0x0000u16.to_be_bytes())?; // Number of additional records
        for atom in CLOUDFLARE_QNAME {
            // Write the length of this atom followed by the string itself
            cursor.write_all(&[atom.len() as u8])?;
            cursor.write_all(atom.as_bytes())?;
        }
        // Finish the qname with a terminating byte (0-length atom).
        cursor.write_all(&[0x00])?;
        cursor.write_all(&TYPE_TXT.to_be_bytes())?;
        cursor.write_all(&CLASS_CH.to_be_bytes())?;

        let len = cursor.position() as usize;
        socket.connect(endpoint)?;
        socket.send(&buf[..len])?;

        Ok(Self {
            socket,
            id,
            buf,
            _ip_type: PhantomData,
        })
    }

    fn read_response(mut self) -> Result<T, Error> {
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
        ensure!(buf.read_u16()? == 0, "unexpected AR value");

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
        ensure!(buf.read_u16()? == TYPE_TXT, "answer is not TXT type");
        ensure!(buf.read_u16()? == CLASS_CH, "answer is not CH class");
        buf.set_position(buf.position() + 4); // Ignore TTL

        let data_len = buf.read_u16()? as usize;
        let txt_len = buf.read_u8()? as usize;
        ensure!(txt_len == data_len - 1, "unexpected txt and data lengths.");

        let start = buf.position() as usize;
        let end = start + txt_len;
        ensure!(response.len() >= end, "unexpected txt answer lengths");

        let txt = std::str::from_utf8(&response[start..end]).ok();
        let answer = txt
            .and_then(|txt| txt.parse::<T>().ok())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "TXT not IP address".to_string()))?;

        Ok(answer)
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
        assert!(v4.is_some());
        assert!(v6.is_some());
        Ok(())
    }
}

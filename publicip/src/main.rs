pub fn main() {
    let (ipv4, ipv6) = publicip::get_both();
    println!(
        "ipv4: {}",
        match ipv4 {
            Some(addr) => addr.to_string(),
            None => "?".into(),
        }
    );
    println!(
        "ipv6: {}",
        match ipv6 {
            Some(addr) => addr.to_string(),
            None => "?".into(),
        }
    );
}

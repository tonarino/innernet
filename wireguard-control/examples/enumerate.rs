use wireguard_control::{Backend, Device};

fn main() {
    let devices = Device::list(Backend::Kernel).unwrap();
    println!("{:?}", devices);
}
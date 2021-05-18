use wgctrl::Device;

fn main() {
    let devices = Device::enumerate().unwrap();

    for device in devices {
        println!("{}", device);
    }
}

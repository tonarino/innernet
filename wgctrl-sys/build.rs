#[cfg(target_os = "linux")]
mod linux {
    use std::{env, path::PathBuf};

    pub fn build_bindings() {
        let bindings = bindgen::Builder::default()
            .rust_target(bindgen::RustTarget::Stable_1_40)
            .derive_default(true)
            .header("c/wireguard.h")
            .impl_debug(true)
            .allowlist_function("wg_.*")
            .bitfield_enum("wg_peer_flags")
            .bitfield_enum("wg_device_flags");

        let bindings = bindings.generate().expect("Unable to generate bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }

    pub fn build_library() {
        cc::Build::new()
            .file("c/wireguard.c")
            .warnings(true)
            .extra_warnings(true)
            .warnings_into_errors(true)
            .flag_if_supported("-Wno-unused-parameter")
            .compile("wireguard");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::build_bindings();
    linux::build_library();
}

#[cfg(not(target_os = "linux"))]
fn main() {}

fn main() {
    // Check frontend-rebuild
    println!("cargo:rerun-if-changed=../ui/dist/index.html");
}

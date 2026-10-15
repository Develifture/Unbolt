fn main() {
    println!("cargo:rerun-if-changed=assets/unbolt.ico");
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon("assets/unbolt.ico")
        .set("ProductName", "Unbolt")
        .set("FileDescription", "Unbolt application manager")
        .set("LegalCopyright", "MIT licensed");
    resource
        .compile()
        .expect("compile Windows icon and version resources");
    println!("cargo:rerun-if-changed=unbolt-helper.manifest");
    let helper = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("unbolt-helper.manifest");
    println!("cargo:rustc-link-arg-bin=unbolt-helper=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin=unbolt-helper=/MANIFESTINPUT:{}",
        helper.display()
    );
    println!("cargo:rerun-if-changed=unbolt.manifest");
    let path = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("unbolt.manifest");
    println!("cargo:rustc-link-arg-bin=unbolt=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin=unbolt=/MANIFESTINPUT:{}",
        path.display()
    );
}

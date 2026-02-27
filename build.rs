fn main() {
    println!("cargo:rerun-if-env-changed=OXMGR_BUILD_VERSION");

    let version = std::env::var("OXMGR_BUILD_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=OXMGR_BUILD_VERSION={version}");
}

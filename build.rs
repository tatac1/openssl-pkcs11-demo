#![deny(rust_2018_idioms, warnings)]

fn main() {
	let openssl_version = std::env::var("DEP_OPENSSL_VERSION_NUMBER").expect("DEP_OPENSSL_VERSION_NUMBER must have been set by openssl-sys");
	let openssl_version = u64::from_str_radix(&openssl_version, 16).expect("DEP_OPENSSL_VERSION_NUMBER must have been set to a valid integer");
	if openssl_version >= 0x01_01_01_00_0 {
		println!("cargo:rustc-cfg=ed25519");
	}
}

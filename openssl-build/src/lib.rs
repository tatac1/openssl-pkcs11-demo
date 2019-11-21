#![deny(rust_2018_idioms, warnings)]

pub fn define_version_number_cfg() {
	let openssl_version = std::env::var("DEP_OPENSSL_VERSION_NUMBER").expect("DEP_OPENSSL_VERSION_NUMBER must have been set by openssl-sys");
	let openssl_version = u64::from_str_radix(&openssl_version, 16).expect("DEP_OPENSSL_VERSION_NUMBER must have been set to a valid integer");
	#[allow(clippy::inconsistent_digit_grouping)]
	{
		if openssl_version >= 0x01_01_00_00_0 {
			println!("cargo:rustc-cfg=ossl110");
		}

		if openssl_version >= 0x01_01_01_00_0 {
			println!("cargo:rustc-cfg=ossl111");
		}
	}
}

pub fn get_c_compiler() -> cc::Build {
	// openssl-sys does not give us a way to find the include directory that it used, so we have to find it ourselves.

	// TODO: Read cross-compiling $TARGET_OPENSSL_{INCLUDE,LIB}_DIR env vars when present instead of pkg-config

	let lib =
		pkg_config::Config::new()
		.cargo_metadata(false) // openssl-sys already did it
		.print_system_libs(false)
		.probe("openssl")
		.unwrap();

	let mut build = cc::Build::new();
	for include_path in lib.include_paths {
		build.include(include_path);
	}

	build.warnings_into_errors(true);

	build
}

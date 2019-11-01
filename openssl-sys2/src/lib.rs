#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	non_camel_case_types,
)]

mod asn1;
pub use asn1::*;

#[cfg(ossl110)]
mod ec;
#[cfg(ossl110)]
pub use ec::*;

#[cfg(not(ossl110))]
mod ecdsa;
#[cfg(not(ossl110))]
pub use ecdsa::*;

mod engine;
pub use engine::*;

mod rsa;
pub use rsa::*;

extern "C" {
	// ENGINE_load_dynamic is a standalone function in 1.0.0 and a wrapper around OPENSSL_init_crypto in 1.1.0

	#[cfg(ossl110)]
	pub fn OPENSSL_init_crypto(opts: u64, settings: *const openssl_sys::OPENSSL_INIT_SETTINGS) -> std::os::raw::c_int;

	#[cfg(not(ossl110))]
	pub fn ENGINE_load_dynamic();
}

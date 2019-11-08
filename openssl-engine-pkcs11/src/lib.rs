#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::shadow_unrelated,
	clippy::use_self,
)]

mod ec_key;

mod engine;

mod rsa;

pub fn load(context: std::sync::Arc<pkcs11::Context>) -> Result<openssl2::FunctionalEngine, openssl2::Error> {
	unsafe {
		engine::Engine::register_once();

		let e = openssl2::StructuralEngine::by_id(std::ffi::CStr::from_bytes_with_nul(engine::ENGINE_ID).unwrap())?;
		let e: openssl2::FunctionalEngine = std::convert::TryInto::try_into(e)?;

		let engine = engine::Engine::new(context);
		engine.save(e.as_ptr())?;

		Ok(e)
	}
}

struct ExData<T> {
	object_handle: pkcs11::Object<T>,
}

/// Prints the error, if any, from evaluating the given callback and converts it to a unit sentinel.
///
/// Intended to be used at FFI boundaries, where a Rust error cannot pass through and must be converted to an integer, nullptr, etc.
fn r#catch<T>(f: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>) -> Result<T, ()> {
	match f() {
		Ok(value) => Ok(value),
		Err(err) => {
			eprintln!("[openssl-engine-pkcs11] Error: {}", err);

			let mut source = err.source();
			while let Some(err) = source {
				eprintln!("[openssl-engine-pkcs11] caused by: {}", err);
				source = err.source();
			}

			Err(())
		},
	}
}

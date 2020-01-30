#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::let_and_return,
	clippy::missing_errors_doc,
	clippy::shadow_unrelated,
	clippy::use_self,
)]

//! This crate implements a custom openssl engine that implements the openssl engine and key methods API in terms of PKCS#11.
//!
//! To use the engine, obtain a [`pkcs11::Context`] and call [`load`]

mod ec_key;

mod engine;

pub(crate) mod ex_data;

mod rsa;

/// Load a new instance of the PKCS#11 openssl engine for the given PKCS#11 context.
pub fn load(context: std::sync::Arc<pkcs11::Context>) -> Result<openssl2::FunctionalEngine, openssl2::Error> {
	unsafe {
		engine::Engine::register_once();

		let e = openssl2::StructuralEngine::by_id(std::ffi::CStr::from_bytes_with_nul(engine::ENGINE_ID).unwrap())?;
		let e: openssl2::FunctionalEngine = std::convert::TryInto::try_into(e)?;

		let engine = engine::Engine::new(context);
		crate::ex_data::set(foreign_types_shared::ForeignType::as_ptr(&e), engine)?;

		Ok(e)
	}
}

openssl_errors::openssl_errors! {
	#[allow(clippy::empty_enum)] // Workaround for https://github.com/sfackler/rust-openssl/issues/1189
	library Error("openssl_pkcs11_engine") {
		functions {
			ENGINE_LOAD_PRIVKEY("engine_load_privkey");
			ENGINE_LOAD_PUBKEY("engine_load_pubkey");

			ENGINE_PKEY_METHS("engine_pkey_meths");

			PKCS11_EC_KEY_SIGN_SIG("pkcs11_ec_key_sign_sig");

			PKCS11_RSA_METHOD_PRIV_ENC("pkcs11_rsa_method_priv_enc");
		}

		reasons {
			MESSAGE("");
		}
	}
}

/// Catches the error, if any, from evaluating the given callback and converts it to a unit sentinel.
/// If an openssl error function reference is provided, it is used to push the error onto the openssl error stack.
/// Otherwise, the error is logged to stderr.
///
/// Intended to be used at FFI boundaries, where a Rust error cannot pass through and must be converted to an integer, nullptr, etc.
fn r#catch<T>(
	function: Option<fn() -> openssl_errors::Function<Error>>,
	f: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, ()> {
	match f() {
		Ok(value) => Ok(value),
		Err(err) => {
			// Technically, the order the errors should be put onto the openssl error stack is from root cause to top error.
			// Unfortunately this is backwards from how Rust errors work, since they are top error to root cause.
			//
			// We could do it the right way by collect()ing into a Vec<&dyn Error> and iterating it backwards,
			// but it seems too wasteful to be worth it. So just put them in the wrong order.

			if let Some(function) = function {
				openssl_errors::put_error!(function(), Error::MESSAGE, "{}", err);
			}
			else {
				eprintln!("[openssl-engine-pkcs11] error: {}", err);
			}

			let mut source = err.source();
			while let Some(err) = source {
				if let Some(function) = function {
					openssl_errors::put_error!(function(), Error::MESSAGE, "{}", err);
				}
				else {
					eprintln!("[openssl-engine-pkcs11] caused by: {}", err);
				}

				source = err.source();
			}

			Err(())
		},
	}
}

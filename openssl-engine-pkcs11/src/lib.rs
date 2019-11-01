#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::shadow_unrelated,
	clippy::use_self,
)]

mod ec_key;

mod engine;

mod rsa;

struct ExData<T> {
	object_handle: pkcs11::Object<T>,
}

fn r#catch<T>(f: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>) -> Result<T, ()> {
	match f() {
		Ok(value) => Ok(value),
		Err(err) => {
			eprintln!("{}", err);

			let mut source = err.source();
			while let Some(err) = source {
				eprintln!("caused by: {}", err);
				source = err.source();
			}

			Err(())
		},
	}
}

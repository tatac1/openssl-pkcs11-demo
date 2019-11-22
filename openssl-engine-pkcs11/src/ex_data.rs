#[derive(Clone, Copy)]
pub(crate) struct ExIndices {
	pub(crate) engine: openssl::ex_data::Index<openssl_sys::ENGINE, crate::engine::Engine>,
	pub(crate) ec_key: openssl::ex_data::Index<openssl_sys::EC_KEY, pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>>,
	pub(crate) rsa: openssl::ex_data::Index<openssl_sys::RSA, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>>,
}

pub(crate) unsafe fn ex_indices() -> ExIndices {
	static mut RESULT: *const ExIndices = std::ptr::null();
	static mut RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
		// If we can't get the ex indices, log the error and swallow it, leaving RESULT as nullptr.
		// After the Once initializer, the code will assert and abort.
		let _ = super::r#catch(None, || {
			extern "C" {
				fn get_engine_ex_index() -> std::os::raw::c_int;
				fn get_ec_key_ex_index() -> std::os::raw::c_int;
				fn get_rsa_ex_index() -> std::os::raw::c_int;
			}

			let engine_ex_index = get_engine_ex_index();
			if engine_ex_index == -1 {
				return Err(format!("could not register ENGINE ex index: {}", openssl::error::ErrorStack::get()).into());
			}

			let ec_key_ex_index = get_ec_key_ex_index();
			if ec_key_ex_index == -1 {
				return Err(format!("could not register EC_KEY ex index: {}", openssl::error::ErrorStack::get()).into());
			}

			let rsa_ex_index = get_rsa_ex_index();
			if rsa_ex_index == -1 {
				return Err(format!("could not register RSA ex index: {}", openssl::error::ErrorStack::get()).into());
			}

			let ex_indices = ExIndices {
				engine: openssl::ex_data::Index::from_raw(engine_ex_index),
				ec_key: openssl::ex_data::Index::from_raw(ec_key_ex_index),
				rsa: openssl::ex_data::Index::from_raw(rsa_ex_index),
			};
			RESULT = Box::into_raw(Box::new(ex_indices));

			Ok(())
		});
	});

	assert!(!RESULT.is_null(), "ex indices could not be initialized");
	*RESULT
}

pub(crate) trait HasExData: Sized {
	type Ty;

	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void;
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int;

	unsafe fn index() -> openssl::ex_data::Index<Self, Self::Ty>;
}

pub(crate) unsafe fn load<T>(this: &T) -> Result<&<T as HasExData>::Ty, openssl2::Error> where T: HasExData {
	let ex_index = <T as HasExData>::index().as_raw();

	let ex_data: *const <T as HasExData>::Ty = openssl2::openssl_returns_nonnull((<T as HasExData>::GET_FN)(
		this,
		ex_index,
	))? as _;

	Ok(&*ex_data)
}

pub(crate) unsafe fn save<T>(this: *mut T, ex_data: <T as HasExData>::Ty) -> Result<(), openssl2::Error> where T: HasExData {
	let ex_index = <T as HasExData>::index().as_raw();

	let ex_data = Box::into_raw(Box::new(ex_data)) as _;

	openssl2::openssl_returns_1((<T as HasExData>::SET_FN)(
		this,
		ex_index,
		ex_data,
	))?;

	Ok(())
}

pub(crate) unsafe fn free<T>(ptr: *mut std::ffi::c_void) where T: HasExData {
	let ptr: *mut <T as HasExData>::Ty = ptr as _;
	if !ptr.is_null() {
		let ex_data = ptr.read();
		drop(ex_data);
	}
}

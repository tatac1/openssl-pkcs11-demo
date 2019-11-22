pub(super) static ENGINE_ID: &[u8] = b"openssl-engine-pkcs11\0";

pub(super) struct Engine {
	context: std::sync::Arc<pkcs11::Context>,
}

impl Engine {
	pub(super) fn new(context: std::sync::Arc<pkcs11::Context>) -> Self {
		Engine {
			context,
		}
	}
}

impl Engine {
	pub(super) unsafe fn register_once() {
		static REGISTER: std::sync::Once = std::sync::Once::new();

		REGISTER.call_once(|| {
			// If we can't complete the registration, log the error and swallow it.
			// The caller will get an error when it tries to look up the engine that failed to be created,
			// so there's no worry about propagating the error from here.
			let _ = super::r#catch(None, || {
				let e = openssl2::openssl_returns_nonnull(openssl_sys2::ENGINE_new())?;

				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_id(
					e,
					std::ffi::CStr::from_bytes_with_nul(ENGINE_ID).unwrap().as_ptr(),
				))?;
				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_name(
					e,
					std::ffi::CStr::from_bytes_with_nul(b"An openssl engine that wraps a PKCS#11 library\0").unwrap().as_ptr(),
				))?;

				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_privkey_function(e, engine_load_privkey))?;
				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_pubkey_function(e, engine_load_pubkey))?;
				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_flags(e, openssl_sys2::ENGINE_FLAGS_BY_ID_COPY))?;

				openssl2::openssl_returns_1(openssl_sys2::ENGINE_add(e))?;

				let e = openssl2::StructuralEngine::from_ptr(e);
				drop(e);

				Ok(())
			});
		});
	}
}

impl crate::ex_data::HasExData for openssl_sys::ENGINE {
	type Ty = crate::engine::Engine;

	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void =
		openssl_sys2::ENGINE_get_ex_data;
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int =
		openssl_sys2::ENGINE_set_ex_data;

	unsafe fn index() -> openssl::ex_data::Index<Self, Self::Ty> {
		crate::ex_data::ex_indices().engine
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn dupf_engine_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::ENGINE>(from_d);
	1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn freef_engine_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::ENGINE>(ptr);
}

unsafe extern "C" fn engine_load_privkey(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	_ui_method: *mut openssl_sys2::UI_METHOD,
	_callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY {
	let result = super::r#catch(Some(|| super::Error::ENGINE_LOAD_PRIVKEY), || {
		let engine = crate::ex_data::load(&*e)?;

		let key_id = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_id: pkcs11::Uri = key_id.parse()?;

		let context = engine.context.clone();
		let slot = context.find_slot(&key_id.slot_identifier)?;

		let session = slot.open_session(false, key_id.pin)?;

		let key_pair = session.get_key_pair(key_id.object_label.as_ref().map(AsRef::as_ref))?;
		match key_pair {
			pkcs11::KeyPair::Ec(public_key, private_key) => {
				let parameters = public_key.parameters()?;

				crate::ex_data::save(
					foreign_types_shared::ForeignType::as_ptr(&parameters),
					private_key,
				)?;

				#[cfg(ossl110)]
				openssl2::openssl_returns_1(openssl_sys2::EC_KEY_set_method(
					foreign_types_shared::ForeignType::as_ptr(&parameters),
					super::ec_key::pkcs11_ec_key_method(),
				))?;
				#[cfg(not(ossl110))]
				openssl2::openssl_returns_1(openssl_sys2::ECDSA_set_method(
					foreign_types_shared::ForeignType::as_ptr(&parameters),
					super::ec_key::pkcs11_ec_key_method(),
				))?;

				let openssl_key = openssl::pkey::PKey::from_ec_key(parameters)?;
				let openssl_key_raw = crate::foreign_type_into_ptr(openssl_key);

				Ok(openssl_key_raw)
			},

			pkcs11::KeyPair::Rsa(public_key, private_key) => {
				let parameters = public_key.parameters()?;

				crate::ex_data::save(
					foreign_types_shared::ForeignType::as_ptr(&parameters),
					private_key,
				)?;

				openssl2::openssl_returns_1(openssl_sys2::RSA_set_method(
					foreign_types_shared::ForeignType::as_ptr(&parameters),
					super::rsa::pkcs11_rsa_method(),
				))?;

				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = crate::foreign_type_into_ptr(openssl_key);

				Ok(openssl_key_raw)
			},
		}
	});
	match result {
		Ok(key) => key,
		Err(()) => std::ptr::null_mut(),
	}
}

unsafe extern "C" fn engine_load_pubkey(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	_ui_method: *mut openssl_sys2::UI_METHOD,
	_callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY {
	let result = super::r#catch(Some(|| super::Error::ENGINE_LOAD_PUBKEY), || {
		let engine = crate::ex_data::load(&*e)?;

		let key_id = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_id: pkcs11::Uri = key_id.parse()?;

		let context = engine.context.clone();
		let slot = context.find_slot(&key_id.slot_identifier)?;

		let session = slot.open_session(false, key_id.pin)?;

		let public_key = session.get_public_key(key_id.object_label.as_ref().map(AsRef::as_ref))?;
		match public_key {
			pkcs11::PublicKey::Ec(public_key) => {
				let parameters = public_key.parameters()?;
				let openssl_key = openssl::pkey::PKey::from_ec_key(parameters)?;
				let openssl_key_raw = crate::foreign_type_into_ptr(openssl_key);
				Ok(openssl_key_raw)
			},

			pkcs11::PublicKey::Rsa(public_key) => {
				let parameters = public_key.parameters()?;
				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = crate::foreign_type_into_ptr(openssl_key);
				Ok(openssl_key_raw)
			},
		}
	});
	match result {
		Ok(key) => key,
		Err(()) => std::ptr::null_mut(),
	}
}

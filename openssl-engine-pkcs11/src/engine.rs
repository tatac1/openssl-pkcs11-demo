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

	unsafe fn from(e: *mut openssl_sys::ENGINE) -> Result<*mut Self, openssl2::Error> {
		let index = get_engine_ex_index();
		let engine = openssl2::openssl_returns_nonnull(openssl_sys2::ENGINE_get_ex_data(e, index) as _)?;
		Ok(engine)
	}

	pub(super) unsafe fn save(self, e: *mut openssl_sys::ENGINE) -> Result<(), openssl2::Error> {
		let index = get_engine_ex_index();
		let engine = Box::into_raw(Box::new(self));
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_ex_data(e, index, engine as _))?;
		Ok(())
	}
}

static REGISTER: std::sync::Once = std::sync::Once::new();

impl Engine {
	pub(super) unsafe fn register_once() {
		REGISTER.call_once(|| {
			let _ = super::r#catch(|| {
				let e = openssl2::openssl_returns_nonnull(openssl_sys2::ENGINE_new())?;

				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_id(
					e,
					std::ffi::CStr::from_bytes_with_nul(ENGINE_ID).unwrap().as_ptr(),
				))?;
				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_name(
					e,
					std::ffi::CStr::from_bytes_with_nul(b"An openssl engine that wraps a PKCS#11 library\0").unwrap().as_ptr(),
				))?;

				openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_finish_function(e, engine_finish))?;
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

unsafe extern "C" fn engine_finish(
	e: *mut openssl_sys::ENGINE,
) -> std::os::raw::c_int {
	let result = super::r#catch(|| {
		let engine = Engine::from(e)?;
		let engine = Box::from_raw(engine);
		drop(engine);
		Ok(())
	});
	match result {
		Ok(()) => 1,
		Err(()) => 0,
	}
}

unsafe extern "C" fn engine_load_privkey(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	_ui_method: *mut openssl_sys2::UI_METHOD,
	_callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY {
	let result = super::r#catch(|| {
		let engine = &*Engine::from(e)?;

		let key_id = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_id: pkcs11::Uri = key_id.parse()?;

		let context = engine.context.clone();
		let slot = context.find_slot(&key_id.slot_identifier)?;

		let session = slot.open_session(false, key_id.pin)?;

		let key_pair = session.get_key_pair(key_id.object_label.as_ref().map(AsRef::as_ref))?;
		match key_pair {
			pkcs11::KeyPair::Ec(public_key, private_key) => {
				let parameters = public_key.parameters()?;

				super::ExData::save_ec_key(
					private_key,
					foreign_types::ForeignType::as_ptr(&parameters),
				)?;

				#[cfg(ossl110)]
				openssl2::openssl_returns_1(openssl_sys2::EC_KEY_set_method(
					foreign_types::ForeignType::as_ptr(&parameters),
					super::ec_key::pkcs11_ec_key_method(),
				))?;
				#[cfg(not(ossl110))]
				openssl2::openssl_returns_1(openssl_sys2::ECDSA_set_method(
					foreign_types::ForeignType::as_ptr(&parameters),
					super::ec_key::pkcs11_ec_key_method(),
				))?;

				let openssl_key = openssl::pkey::PKey::from_ec_key(parameters)?;
				let openssl_key_raw = foreign_types::ForeignType::as_ptr(&openssl_key);
				std::mem::forget(openssl_key);

				Ok(openssl_key_raw)
			},

			pkcs11::KeyPair::Rsa(public_key, private_key) => {
				let parameters = public_key.parameters()?;

				super::ExData::save_rsa(
					private_key,
					foreign_types::ForeignType::as_ptr(&parameters),
				)?;

				openssl2::openssl_returns_1(openssl_sys2::RSA_set_method(
					foreign_types::ForeignType::as_ptr(&parameters),
					super::rsa::pkcs11_rsa_method(),
				))?;

				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = foreign_types::ForeignType::as_ptr(&openssl_key);
				std::mem::forget(openssl_key);

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
	let result = super::r#catch(|| {
		let engine = &*Engine::from(e)?;

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
				let openssl_key_raw = foreign_types::ForeignType::as_ptr(&openssl_key);
				std::mem::forget(openssl_key);
				Ok(openssl_key_raw)
			},

			pkcs11::PublicKey::Rsa(public_key) => {
				let parameters = public_key.parameters()?;
				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = foreign_types::ForeignType::as_ptr(&openssl_key);
				std::mem::forget(openssl_key);
				Ok(openssl_key_raw)
			},
		}
	});
	match result {
		Ok(key) => key,
		Err(()) => std::ptr::null_mut(),
	}
}

extern "C" {
	fn get_engine_ex_index() -> std::os::raw::c_int;
}

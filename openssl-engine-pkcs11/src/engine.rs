static mut CMD_DEFNS: *const openssl_sys2::ENGINE_CMD_DEFN = std::ptr::null_mut();

#[no_mangle]
unsafe extern "C" fn openssl_engine_pkcs11_bind(e: *mut openssl_sys::ENGINE, _id: *const std::os::raw::c_char) -> std::os::raw::c_int {
	if CMD_DEFNS.is_null() {
		let cmd_defns = Box::new([
			openssl_sys2::ENGINE_CMD_DEFN {
				cmd_num: get_ENGINE_CMD_BASE(),
				cmd_name: b"PKCS11_CONTEXT\0".as_ptr() as _,
				cmd_desc: b"Pass in *const pkcs11::Context through void* parameter\0".as_ptr() as _,
				cmd_flags: get_ENGINE_CMD_FLAG_STRING(),
			},
			openssl_sys2::ENGINE_CMD_DEFN {
				cmd_num: 0,
				cmd_name: std::ptr::null(),
				cmd_desc: std::ptr::null(),
				cmd_flags: 0,
			},
		]);
		CMD_DEFNS = cmd_defns.as_ptr();
		std::mem::forget(cmd_defns);
	}

	let result = super::r#catch(|| {
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_id(
			e,
			std::ffi::CStr::from_bytes_with_nul(b"openssl-engine-pkcs11\0").unwrap().as_ptr(),
		))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_name(
			e,
			std::ffi::CStr::from_bytes_with_nul(b"An openssl engine that wraps a PKCS#11 library\0").unwrap().as_ptr(),
		))?;

		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_init_function(e, engine_init))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_finish_function(e, engine_finish))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_ctrl_function(e, engine_ctrl))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_privkey_function(e, engine_load_privkey))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_pubkey_function(e, engine_load_pubkey))?;

		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_cmd_defns(e, CMD_DEFNS))?;

		Ok(())
	});
	match result {
		Ok(()) => 1,
		Err(()) => 0,
	}
}

unsafe extern "C" fn engine_init(
	e: *mut openssl_sys::ENGINE,
) -> std::os::raw::c_int {
	let result = super::r#catch(|| {
		let engine = Engine { context: None };
		engine.save(e)?;
		Ok(())
	});
	match result {
		Ok(()) => 1,
		Err(()) => 0,
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

unsafe extern "C" fn engine_ctrl(
	e: *mut openssl_sys::ENGINE,
	cmd_num: std::os::raw::c_int,
	_: std::os::raw::c_long,
	p: *mut std::ffi::c_void,
	_: Option<unsafe extern "C" fn()>,
) -> std::os::raw::c_int {
	if cmd_num == std::convert::TryInto::try_into(get_ENGINE_CMD_BASE()).expect("c_uint -> c_int") {
		let result = super::r#catch(|| {
			let engine = Engine::from(e)?;
			let context: *const pkcs11::Context = p as _;
			let context = std::sync::Arc::from_raw(context);
			(*engine).context = Some(context);
			Ok(())
		});
		match result {
			Ok(()) => 1,
			Err(()) => 0,
		}
	}
	else {
		-1 // Error value return is negative number, not 0
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

		let session = engine.open_session(key_id)?;

		let key_pair = session.get_key_pair()?;
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

		let session = engine.open_session(key_id)?;

		let public_key = session.get_public_key()?;
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

struct Engine {
	context: Option<std::sync::Arc<pkcs11::Context>>,
}

impl Engine {
	unsafe fn from(e: *mut openssl_sys::ENGINE) -> Result<*mut Self, openssl2::Error> {
		let index = get_engine_ex_index();
		let engine = openssl2::openssl_returns_nonnull(openssl_sys2::ENGINE_get_ex_data(e, index) as _)?;
		Ok(engine)
	}

	unsafe fn save(self, e: *mut openssl_sys::ENGINE) -> Result<(), openssl2::Error> {
		let index = get_engine_ex_index();
		let engine = Box::into_raw(Box::new(self));
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_ex_data(e, index, engine as _))?;
		Ok(())
	}

	unsafe fn open_session(
		&self,
		key_id: *const std::os::raw::c_char,
	) -> Result<std::sync::Arc<pkcs11::Session>, Box<dyn std::error::Error>> {
		let context = self.context.clone().expect("PKCS11_CONTEXT not set on engine");

		let key_id = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_id: pkcs11::Uri = key_id.parse()?;

		let slot = match key_id.slot_identifier {
			pkcs11::UriSlotIdentifier::Label(label) => {
				let mut slot = None;
				for context_slot in context.slots()? {
					let token_info = context_slot.token_info()?;
					if !token_info.flags.has(pkcs11_sys::CKF_TOKEN_INITIALIZED) {
						continue;
					}

					let slot_label = String::from_utf8_lossy(&token_info.label).trim().to_owned();
					if slot_label != label {
						continue;
					}

					slot = Some(context_slot);
					break;
				}

				slot.ok_or("could not find slot with matching label")?
			},

			pkcs11::UriSlotIdentifier::SlotId(slot_id) => context.slot(slot_id),
		};

		let session = slot.open_session(false, key_id.pin.as_ref().map(AsRef::as_ref))?;
		Ok(session)
	}
}

extern "C" {
	fn get_ENGINE_CMD_BASE() -> std::os::raw::c_uint;
	fn get_ENGINE_CMD_FLAG_STRING() -> std::os::raw::c_uint;
	fn get_engine_ex_index() -> std::os::raw::c_int;
}

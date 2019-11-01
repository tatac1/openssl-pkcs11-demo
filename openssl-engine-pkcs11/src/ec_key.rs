#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn freef_ec_key_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	let ptr: *mut super::ExData<openssl::ec::EcKey<()>> = ptr as _;
	if !ptr.is_null() {
		let ex_data = ptr.read();
		drop(ex_data);
	}
}

#[cfg(ossl110)]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::EC_KEY_METHOD {
	static mut RESULT: *const openssl_sys2::EC_KEY_METHOD = std::ptr::null();

	if RESULT.is_null() {
		let openssl_ec_key_method = openssl_sys2::EC_KEY_OpenSSL();
		let pkcs11_ec_key_method = openssl_sys2::EC_KEY_METHOD_new(openssl_ec_key_method);

		let mut openssl_ec_key_sign = None;
		openssl_sys2::EC_KEY_METHOD_get_sign(
			pkcs11_ec_key_method,
			&mut openssl_ec_key_sign,
			std::ptr::null_mut(),
			std::ptr::null_mut(),
		);
		openssl_sys2::EC_KEY_METHOD_set_sign(
			pkcs11_ec_key_method,
			openssl_ec_key_sign, // Reuse openssl's function to compute the digest
			None, // Disable sign_setup because pkcs11_ec_key_sign_sig doesn't need the pre-computed kinv and rp
			Some(pkcs11_ec_key_sign_sig),
		);

		RESULT = pkcs11_ec_key_method as _
	}

	RESULT
}

#[cfg(not(ossl110))]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::ECDSA_METHOD {
	static mut RESULT: *const openssl_sys2::ECDSA_METHOD = std::ptr::null();

	if RESULT.is_null() {
		let openssl_ec_key_method = openssl_sys2::ECDSA_OpenSSL();
		let pkcs11_ec_key_method = openssl_sys2::ECDSA_METHOD_new(openssl_ec_key_method);

		openssl_sys2::ECDSA_METHOD_set_sign(
			pkcs11_ec_key_method,
			Some(pkcs11_ec_key_sign_sig),
		);

		RESULT = pkcs11_ec_key_method as _
	}

	RESULT
}

unsafe extern "C" fn pkcs11_ec_key_sign_sig(
	dgst: *const std::os::raw::c_uchar,
	dlen: std::os::raw::c_int,
	_kinv: *const openssl_sys::BIGNUM,
	_r: *const openssl_sys::BIGNUM,
	eckey: *mut openssl_sys::EC_KEY,
) -> *mut openssl_sys::ECDSA_SIG {
	let result = super::r#catch(|| {
		let ex_data = super::ExData::from_ec_key(eckey)?;
		let object_handle = &mut (*ex_data).object_handle;

		let digest = std::slice::from_raw_parts(dgst, std::convert::TryInto::try_into(dlen).expect("c_int -> usize"));
		let signature_len = openssl_sys2::ECDSA_size(eckey);
		let mut signature = vec![0_u8; std::convert::TryInto::try_into(signature_len).expect("c_int -> usize")];
		let signature_len = object_handle.sign(digest, &mut signature)?;
		let signature_len: usize = std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> usize");

		let r = openssl::bn::BigNum::from_slice(&signature[..(signature_len / 2)])?;
		let s = openssl::bn::BigNum::from_slice(&signature[(signature_len / 2)..signature_len])?;
		let signature = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;

		let result = foreign_types::ForeignType::as_ptr(&signature);
		std::mem::forget(signature);
		Ok(result)
	});
	match result {
		Ok(signature) => signature,
		Err(()) => std::ptr::null_mut(),
	}
}

extern "C" {
	fn get_ec_key_ex_index() -> std::os::raw::c_int;
}

impl<T> super::ExData<openssl::ec::EcKey<T>> {
	unsafe fn from_ec_key(key: *mut openssl_sys::EC_KEY) -> Result<*mut Self, openssl2::Error> {
		let ex_index = get_ec_key_ex_index();

		#[cfg(ossl110)]
		let ex_data = openssl2::openssl_returns_nonnull(openssl_sys2::EC_KEY_get_ex_data(
			key,
			ex_index,
		))? as _;
		#[cfg(not(ossl110))]
		let ex_data = openssl2::openssl_returns_nonnull(openssl_sys2::ECDSA_get_ex_data(
			key,
			ex_index,
		))? as _;

		Ok(ex_data)
	}

	pub(super) unsafe fn save_ec_key(
		object_handle: pkcs11::Object<T>,
		key: *mut openssl_sys::EC_KEY,
	) -> Result<(), openssl2::Error> {
		let ex_index = get_ec_key_ex_index();

		let ex_data = Box::into_raw(Box::new(super::ExData::<T> {
			object_handle,
		})) as _;

		#[cfg(ossl110)]
		openssl2::openssl_returns_1(openssl_sys2::EC_KEY_set_ex_data(
			key,
			ex_index,
			ex_data,
		))?;
		#[cfg(not(ossl110))]
		openssl2::openssl_returns_1(openssl_sys2::ECDSA_set_ex_data(
			key,
			ex_index,
			ex_data,
		))?;

		Ok(())
	}
}

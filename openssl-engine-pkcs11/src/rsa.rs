#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn freef_rsa_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	let ptr: *mut super::ExData<openssl::rsa::Rsa<()>> = ptr as _;
	if !ptr.is_null() {
		let ex_data = ptr.read();
		drop(ex_data);
	}
}

pub(super) unsafe fn pkcs11_rsa_method() -> *const openssl_sys2::RSA_METHOD {
	static mut RESULT: *const openssl_sys2::RSA_METHOD = std::ptr::null();

	if RESULT.is_null() {
		let openssl_rsa_method = openssl_sys2::RSA_get_default_method();
		let pkcs11_rsa_method = openssl_sys2::RSA_meth_dup(openssl_rsa_method);

		openssl_sys2::RSA_meth_set_flags(pkcs11_rsa_method, 0);

		// Don't override openssl's RSA signing function (via RSA_meth_set_sign).
		// Let it compute the digest, and only override the final step to encrypt that digest.
		openssl_sys2::RSA_meth_set_priv_enc(pkcs11_rsa_method, pkcs11_rsa_method_priv_enc);

		openssl_sys2::RSA_meth_set_priv_dec(pkcs11_rsa_method, pkcs11_rsa_method_priv_dec);

		RESULT = pkcs11_rsa_method as _
	}

	RESULT
}

unsafe extern "C" fn pkcs11_rsa_method_priv_enc(
	flen: std::os::raw::c_int,
	from: *const std::os::raw::c_uchar,
	to: *mut std::os::raw::c_uchar,
	rsa: *mut openssl_sys::RSA,
	padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	let result = super::r#catch(|| {
		let ex_data = super::ExData::from_rsa(rsa)?;
		let object_handle = &mut (*ex_data).object_handle;

		let mechanism = match padding {
			openssl_sys::RSA_PKCS1_PADDING => pkcs11_sys::CKM_RSA_PKCS,
			openssl_sys::RSA_NO_PADDING => pkcs11_sys::CKM_RSA_X_509,
			padding => return Err(format!("unrecognized RSA padding scheme 0x{:08x}", padding).into()),
		};
		let digest = std::slice::from_raw_parts(from, std::convert::TryInto::try_into(flen).expect("c_int -> usize"));
		let signature_len = openssl_sys2::RSA_size(rsa);
		let mut signature = std::slice::from_raw_parts_mut(to, std::convert::TryInto::try_into(signature_len).expect("c_int -> usize"));
		let signature_len = object_handle.sign(mechanism, digest, &mut signature)?;
		let signature_len = std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> c_int");

		Ok(signature_len)
	});
	match result {
		Ok(signature_len) => signature_len,
		Err(()) => -1,
	}
}

unsafe extern "C" fn pkcs11_rsa_method_priv_dec(
	_flen: std::os::raw::c_int,
	_from: *const std::os::raw::c_uchar,
	_to: *mut std::os::raw::c_uchar,
	_rsa: *mut openssl_sys::RSA,
	_padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	// TODO

	-1
}

extern "C" {
	fn get_rsa_ex_index() -> std::os::raw::c_int;
}

impl<T> super::ExData<openssl::rsa::Rsa<T>> {
	unsafe fn from_rsa(key: *mut openssl_sys::RSA) -> Result<*mut Self, openssl2::Error> {
		let ex_index = get_rsa_ex_index();
		let ex_data = openssl2::openssl_returns_nonnull(openssl_sys2::RSA_get_ex_data(
			key,
			ex_index,
		))? as _;
		Ok(ex_data)
	}

	pub(super) unsafe fn save_rsa(
		object_handle: pkcs11::Object<T>,
		key: *mut openssl_sys::RSA,
	) -> Result<(), openssl2::Error> {
		let ex_index = get_rsa_ex_index();

		let ex_data = Box::into_raw(Box::new(super::ExData::<T> {
			object_handle,
		})) as _;
		openssl2::openssl_returns_1(openssl_sys2::RSA_set_ex_data(
			key,
			ex_index,
			ex_data,
		))?;

		Ok(())
	}
}

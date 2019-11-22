impl crate::ex_data::HasExData for openssl_sys::RSA {
	type Ty = pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>;

	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void =
		openssl_sys2::RSA_get_ex_data;
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int =
		openssl_sys2::RSA_set_ex_data;

	unsafe fn index() -> openssl::ex_data::Index<Self, Self::Ty> {
		crate::ex_data::ex_indices().rsa
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn dupf_rsa_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::RSA>(from_d);
	1
}

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
	crate::ex_data::free::<openssl_sys::RSA>(ptr);
}

pub(super) unsafe fn pkcs11_rsa_method() -> *const openssl_sys::RSA_METHOD {
	static mut RESULT: *const openssl_sys::RSA_METHOD = std::ptr::null();
	static mut RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
		let openssl_rsa_method = openssl_sys2::RSA_get_default_method();
		let pkcs11_rsa_method = openssl_sys2::RSA_meth_dup(openssl_rsa_method);

		openssl_sys2::RSA_meth_set_flags(pkcs11_rsa_method, 0);

		// Don't override openssl's RSA signing function (via RSA_meth_set_sign).
		// Let it compute the digest, and only override the final step to encrypt that digest.
		openssl_sys2::RSA_meth_set_priv_enc(pkcs11_rsa_method, pkcs11_rsa_method_priv_enc);

		openssl_sys2::RSA_meth_set_priv_dec(pkcs11_rsa_method, pkcs11_rsa_method_priv_dec);

		RESULT = pkcs11_rsa_method as _
	});

	RESULT
}

unsafe extern "C" fn pkcs11_rsa_method_priv_enc(
	flen: std::os::raw::c_int,
	from: *const std::os::raw::c_uchar,
	to: *mut std::os::raw::c_uchar,
	rsa: *mut openssl_sys::RSA,
	padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::PKCS11_RSA_METHOD_PRIV_ENC), || {
		let object_handle = crate::ex_data::get(&*rsa)?;

		let mechanism = match padding {
			openssl_sys::RSA_PKCS1_PADDING => pkcs11_sys::CKM_RSA_PKCS,
			openssl_sys::RSA_NO_PADDING => pkcs11_sys::CKM_RSA_X_509,
			padding => return Err(format!("unrecognized RSA padding scheme 0x{:08x}", padding).into()),
		};

		let digest = std::slice::from_raw_parts(from, std::convert::TryInto::try_into(flen).expect("c_int -> usize"));

		// openssl requires that `to` has space for `RSA_size(rsa)` bytes. Trust the caller.
		let signature_len = {
			let rsa: &openssl::rsa::RsaRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(rsa);
			rsa.size()
		};
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

impl crate::ex_data::HasExData for openssl_sys::EC_KEY {
	type Ty = pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>;

	#[cfg(ossl110)]
	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void =
		openssl_sys2::EC_KEY_get_ex_data;
	#[cfg(not(ossl110))]
	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void =
		openssl_sys2::ECDSA_get_ex_data;

	#[cfg(ossl110)]
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int =
		openssl_sys2::EC_KEY_set_ex_data;
	#[cfg(not(ossl110))]
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int =
		openssl_sys2::ECDSA_set_ex_data;

	unsafe fn index() -> openssl::ex_data::Index<Self, Self::Ty> {
		crate::ex_data::ex_indices().ec_key
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn dupf_ec_key_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	_idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::EC_KEY>(from_d);
	1
}

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
	crate::ex_data::free::<openssl_sys::EC_KEY>(ptr);
}

#[cfg(ossl110)]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::EC_KEY_METHOD {
	static mut RESULT: *const openssl_sys2::EC_KEY_METHOD = std::ptr::null();
	static mut RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
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
	});

	RESULT
}

#[cfg(not(ossl110))]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::ECDSA_METHOD {
	static mut RESULT: *const openssl_sys2::ECDSA_METHOD = std::ptr::null();
	static mut RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
		let openssl_ec_key_method = openssl_sys2::ECDSA_OpenSSL();
		let pkcs11_ec_key_method = openssl_sys2::ECDSA_METHOD_new(openssl_ec_key_method);

		openssl_sys2::ECDSA_METHOD_set_sign(
			pkcs11_ec_key_method,
			Some(pkcs11_ec_key_sign_sig),
		);

		RESULT = pkcs11_ec_key_method as _
	});

	RESULT
}

unsafe extern "C" fn pkcs11_ec_key_sign_sig(
	dgst: *const std::os::raw::c_uchar,
	dlen: std::os::raw::c_int,
	_kinv: *const openssl_sys::BIGNUM,
	_r: *const openssl_sys::BIGNUM,
	eckey: *mut openssl_sys::EC_KEY,
) -> *mut openssl_sys::ECDSA_SIG {
	let result = super::r#catch(Some(|| super::Error::PKCS11_EC_KEY_SIGN_SIG), || {
		let object_handle = crate::ex_data::get(&*eckey)?;

		// Truncate dgst if it's longer than the key order length. Eg The digest input for a P-256 key can only be 32 bytes.
		//
		// softhsm does this inside its C_Sign impl, but tpm2-pkcs11 does not, and the PKCS#11 spec does not opine on the matter.
		// So we need to truncate the digest ourselves.
		let dlen = {
			let eckey: &openssl::ec::EcKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(eckey);
			let group = eckey.group();
			let mut order = openssl::bn::BigNum::new()?;
			let mut big_num_context = openssl::bn::BigNumContext::new()?;
			group.order(&mut order, &mut big_num_context)?;
			let order_num_bits = order.num_bits();
			if dlen.saturating_mul(8) > order_num_bits {
				(order_num_bits + 7) / 8
			}
			else {
				dlen
			}
		};

		let digest = std::slice::from_raw_parts(dgst, std::convert::TryInto::try_into(dlen).expect("c_int -> usize"));

		// TODO: Old versions of tpm2-pkcs11 return DER-encoded ECDSA signature (sequence of two integers, r and s).
		// Other PKCS#11 libraries, and tpm2-pkcs11 with the fix in
		// https://github.com/tpm2-software/tpm2-pkcs11/commit/34702b71afa8621ffdb542c058f8b77a9ca18001 ,
		// return just the raw integers.
		//
		// So support these old versions by reserving a buffer big enough for the DER-encoded object.
		// The DER-encoded object is the larger format.
		// Then attempt to first deserialize the output as a DER signature, and fall back to parsing the output as two raw integers.
		//
		// Once we're able to drop support for this old tpm2-pkcs11, we should remove this.

		let signature_len = openssl_sys2::ECDSA_size(eckey);
		let mut signature = vec![0_u8; std::convert::TryInto::try_into(signature_len).expect("c_int -> usize")];
		let signature_len = object_handle.sign(digest, &mut signature)?;
		let signature_len: usize = std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> usize");
		let signature =
			if let Ok(signature) = openssl::ecdsa::EcdsaSig::from_der(&signature[..signature_len]) {
				signature
			}
			else {
				let r = openssl::bn::BigNum::from_slice(&signature[..(signature_len / 2)])?;
				let s = openssl::bn::BigNum::from_slice(&signature[(signature_len / 2)..signature_len])?;
				openssl::ecdsa::EcdsaSig::from_private_components(r, s)?
			};
		let result = openssl2::foreign_type_into_ptr(signature);

		Ok(result)
	});
	match result {
		Ok(signature) => signature,
		Err(()) => std::ptr::null_mut(),
	}
}

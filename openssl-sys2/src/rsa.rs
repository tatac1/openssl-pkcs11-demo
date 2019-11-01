//! `rsa.h`

#[repr(C)]
pub struct RSA_METHOD([u8; 0]);

extern "C" {
	pub fn RSA_size(
		rsa: *const openssl_sys::RSA,
	) -> std::os::raw::c_int;

	pub fn RSA_get_ex_data(
		r: *const openssl_sys::RSA,
		idx: std::os::raw::c_int,
	) -> *mut std::ffi::c_void;
	pub fn RSA_set_ex_data(
		r: *mut openssl_sys::RSA,
		idx: std::os::raw::c_int,
		arg: *mut std::ffi::c_void,
	) -> std::os::raw::c_int;

	pub fn RSA_get_method(
		rsa: *const openssl_sys::RSA,
	) -> *const RSA_METHOD;
	pub fn RSA_set_method(
		rsa: *mut openssl_sys::RSA,
		meth: *const RSA_METHOD,
	) -> std::os::raw::c_int;

	pub fn RSA_get_default_method() -> *const RSA_METHOD;
}

extern "C" {
	pub fn RSA_meth_dup(
		meth: *const RSA_METHOD,
	) -> *mut RSA_METHOD;
	pub fn RSA_meth_set_flags(
		meth: *mut RSA_METHOD,
		flags: std::os::raw::c_int,
	) -> std::os::raw::c_int;
	pub fn RSA_meth_set_priv_enc(
		rsa: *mut RSA_METHOD,
		priv_enc: unsafe extern "C" fn(
			flen: std::os::raw::c_int,
			from: *const std::os::raw::c_uchar,
			to: *mut std::os::raw::c_uchar,
			rsa: *mut openssl_sys::RSA,
			padding: std::os::raw::c_int,
		) -> std::os::raw::c_int,
	) -> std::os::raw::c_int;
	pub fn RSA_meth_set_priv_dec(
		rsa: *mut RSA_METHOD,
		priv_dec: unsafe extern "C" fn(
			flen: std::os::raw::c_int,
			from: *const std::os::raw::c_uchar,
			to: *mut std::os::raw::c_uchar,
			rsa: *mut openssl_sys::RSA,
			padding: std::os::raw::c_int,
		) -> std::os::raw::c_int,
	) -> std::os::raw::c_int;
}

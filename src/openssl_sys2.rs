pub(crate) const OPENSSL_INIT_ENGINE_DYNAMIC: u64 = 0x0000_0400;

#[repr(C)]
pub struct UI_METHOD([u8; 0]);

#[link(name = "ssl")]
extern "C" {
	pub(crate) fn OPENSSL_init_crypto(opts: u64, settings: *const openssl_sys::OPENSSL_INIT_SETTINGS) -> std::os::raw::c_int;

	/// Deserializes a DER-encoded octet string.
	///
	/// The various subtypes of ASN1_STRING, such as ASN1_OCTET_STRING, are just typedefs to ASN1_STRING.
	/// They only exist so that the DER functions, such as d2i_ASN1_OCTET_STRING, are unique for the corresponding DER type.
	///
	/// So despite being called d2i_ASN1_OCTET_STRING, this function really does operate on ASN1_STRING instances.
	pub(crate) fn d2i_ASN1_OCTET_STRING(
		a: *mut *mut openssl_sys::ASN1_STRING,
		ppin: *mut *const std::os::raw::c_char,
		length: std::os::raw::c_long,
	) -> *mut openssl_sys::ASN1_STRING;


	// engine.h

	pub(crate) fn ENGINE_by_id(id: *const std::os::raw::c_char) -> *mut openssl_sys::ENGINE;
	pub(crate) fn ENGINE_ctrl_cmd(
		e: *mut openssl_sys::ENGINE,
		cmd_name: *const std::os::raw::c_char,
		i: std::os::raw::c_long,
		p: *mut std::ffi::c_void,
		f: Option<unsafe extern "C" fn()>,
		cmd_optional: std::os::raw::c_int,
	) -> std::os::raw::c_int;
	pub(crate) fn ENGINE_finish(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub(crate) fn ENGINE_free(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub(crate) fn ENGINE_get_name(e: *const openssl_sys::ENGINE) -> *const std::os::raw::c_char;
	pub(crate) fn ENGINE_init(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub(crate) fn ENGINE_load_private_key(
		e: *mut openssl_sys::ENGINE,
		key_id: *const std::os::raw::c_char,
		ui_method: *mut UI_METHOD,
		callback_data: *mut std::ffi::c_void,
	) -> *mut openssl_sys::EVP_PKEY;
	pub(crate) fn ENGINE_load_public_key(
		e: *mut openssl_sys::ENGINE,
		key_id: *const std::os::raw::c_char,
		ui_method: *mut UI_METHOD,
		callback_data: *mut std::ffi::c_void,
	) -> *mut openssl_sys::EVP_PKEY;
}

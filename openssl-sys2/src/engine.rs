//! `engine.h`

// Using engines

pub const OPENSSL_INIT_ENGINE_DYNAMIC: u64 = 0x0000_0400;

#[repr(C)]
pub struct UI_METHOD([u8; 0]);

extern "C" {
	pub fn ENGINE_by_id(id: *const std::os::raw::c_char) -> *mut openssl_sys::ENGINE;
	pub fn ENGINE_ctrl_cmd(
		e: *mut openssl_sys::ENGINE,
		cmd_name: *const std::os::raw::c_char,
		i: std::os::raw::c_long,
		p: *mut std::ffi::c_void,
		f: Option<unsafe extern "C" fn()>,
		cmd_optional: std::os::raw::c_int,
	) -> std::os::raw::c_int;
	pub fn ENGINE_finish(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub fn ENGINE_free(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub fn ENGINE_get_name(e: *const openssl_sys::ENGINE) -> *const std::os::raw::c_char;
	pub fn ENGINE_init(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
	pub fn ENGINE_load_private_key(
		e: *mut openssl_sys::ENGINE,
		key_id: *const std::os::raw::c_char,
		ui_method: *mut UI_METHOD,
		callback_data: *mut std::ffi::c_void,
	) -> *mut openssl_sys::EVP_PKEY;
	pub fn ENGINE_load_public_key(
		e: *mut openssl_sys::ENGINE,
		key_id: *const std::os::raw::c_char,
		ui_method: *mut UI_METHOD,
		callback_data: *mut std::ffi::c_void,
	) -> *mut openssl_sys::EVP_PKEY;
}


// Implementing engines

#[repr(C)]
pub struct ENGINE_CMD_DEFN {
	pub cmd_num: std::os::raw::c_uint,
	pub cmd_name: *const std::os::raw::c_char,
	pub cmd_desc: *const std::os::raw::c_char,
	pub cmd_flags: std::os::raw::c_uint,
}

pub type ENGINE_CTRL_FUNC_PTR = unsafe extern "C" fn(
	e: *mut openssl_sys::ENGINE,
	cmd_num: std::os::raw::c_int,
	i: std::os::raw::c_long,
	p: *mut std::ffi::c_void,
	f: Option<unsafe extern "C" fn()>,
) -> std::os::raw::c_int;
pub type ENGINE_GEN_INT_FUNC_PTR = unsafe extern "C" fn(
	e: *mut openssl_sys::ENGINE,
) -> std::os::raw::c_int;
pub type ENGINE_LOAD_KEY_PTR = unsafe extern "C" fn(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	ui_method: *mut UI_METHOD,
	callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY;

extern "C" {
	pub fn ENGINE_get_ex_data(
		e: *const openssl_sys::ENGINE,
		idx: std::os::raw::c_int,
	) -> *mut std::ffi::c_void;
	pub fn ENGINE_set_cmd_defns(
		e: *mut openssl_sys::ENGINE,
		defns: *const ENGINE_CMD_DEFN,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_ex_data(
		e: *mut openssl_sys::ENGINE,
		idx: std::os::raw::c_int,
		arg: *mut std::ffi::c_void,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_finish_function(
		e: *mut openssl_sys::ENGINE,
		ctrl_f: ENGINE_GEN_INT_FUNC_PTR,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_id(
		e: *mut openssl_sys::ENGINE,
		id: *const std::os::raw::c_char,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_init_function(
		e: *mut openssl_sys::ENGINE,
		ctrl_f: ENGINE_GEN_INT_FUNC_PTR,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_name(
		e: *mut openssl_sys::ENGINE,
		name: *const std::os::raw::c_char,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_ctrl_function(
		e: *mut openssl_sys::ENGINE,
		ctrl_f: ENGINE_CTRL_FUNC_PTR,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_load_privkey_function(
		e: *mut openssl_sys::ENGINE,
		loadpriv_f: ENGINE_LOAD_KEY_PTR,
	) -> std::os::raw::c_int;
	pub fn ENGINE_set_load_pubkey_function(
		e: *mut openssl_sys::ENGINE,
		loadpub_f: ENGINE_LOAD_KEY_PTR,
	) -> std::os::raw::c_int;
}

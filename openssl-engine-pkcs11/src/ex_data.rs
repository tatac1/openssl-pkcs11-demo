#[derive(Clone, Copy)]
pub(crate) struct ExIndices {
	pub(crate) engine: openssl::ex_data::Index<openssl_sys::ENGINE, crate::engine::Engine>,
	pub(crate) ec_key: openssl::ex_data::Index<openssl_sys::EC_KEY, pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>>,
	pub(crate) rsa: openssl::ex_data::Index<openssl_sys::RSA, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>>,
}

static EX_INDICES: std::sync::atomic::AtomicPtr<ExIndices> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

pub(crate) fn ex_indices() -> ExIndices {
	let ex_indices = EX_INDICES.load(std::sync::atomic::Ordering::Acquire);
	assert!(!ex_indices.is_null(), "EX_INDICES accessed before it was initialized");
	unsafe { *ex_indices }
}

pub(crate) unsafe fn set_ex_indices(
	engine: openssl::ex_data::Index<openssl_sys::ENGINE, crate::engine::Engine>,
	ec_key: openssl::ex_data::Index<openssl_sys::EC_KEY, pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>>,
	rsa: openssl::ex_data::Index<openssl_sys::RSA, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>>,
) {
	let ex_indices = ExIndices {
		engine,
		ec_key,
		rsa,
	};
	let ex_indices = Box::into_raw(Box::new(ex_indices));
	EX_INDICES.store(ex_indices, std::sync::atomic::Ordering::Release);
}

pub(crate) trait HasExData: Sized {
	type Ty;

	const GET_FN: unsafe extern "C" fn(this: *const Self, idx: std::os::raw::c_int) -> *mut std::ffi::c_void;
	const SET_FN: unsafe extern "C" fn(this: *mut Self, idx: std::os::raw::c_int, arg: *mut std::ffi::c_void) -> std::os::raw::c_int;

	fn index() -> openssl::ex_data::Index<Self, Self::Ty>;
}

pub(crate) unsafe fn load<T>(this: &T) -> Result<&<T as HasExData>::Ty, openssl2::Error> where T: HasExData {
	let ex_index = <T as HasExData>::index().as_raw();

	let ex_data: *const <T as HasExData>::Ty = openssl2::openssl_returns_nonnull((<T as HasExData>::GET_FN)(
		this,
		ex_index,
	))? as _;

	Ok(&*ex_data)
}

pub(crate) unsafe fn save<T>(this: *mut T, ex_data: <T as HasExData>::Ty) -> Result<(), openssl2::Error> where T: HasExData {
	let ex_index = <T as HasExData>::index().as_raw();

	let ex_data = Box::into_raw(Box::new(ex_data)) as _;

	openssl2::openssl_returns_1((<T as HasExData>::SET_FN)(
		this,
		ex_index,
		ex_data,
	))?;

	Ok(())
}

pub(crate) unsafe fn free<T>(ptr: *mut std::ffi::c_void) where T: HasExData {
	let ptr: *mut <T as HasExData>::Ty = ptr as _;
	if !ptr.is_null() {
		let ex_data = ptr.read();
		drop(ex_data);
	}
}

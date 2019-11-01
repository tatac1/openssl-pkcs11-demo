lazy_static::lazy_static! {
	/// Used to memoize [`Context`]s to PKCS#11 libraries.
	///
	/// The PKCS#11 spec allows implementations to reject multiple successive calls to C_Initialize by returning CKR_CRYPTOKI_ALREADY_INITIALIZED.
	/// We can't just ignore the error and create a Context anyway (*), because each Context's Drop impl will call C_Finalize
	/// and we'll have the equivalent of a double-free.
	///
	/// But we don't want users to keep track of this, so we memoize Contexts based on the library path and returns the same Context for
	/// multiple requests to load the same library.
	///
	/// However if the memoizing map were to hold a strong reference to the Context, then the Context would never be released even after the user dropped theirs,
	/// so we need the map to specifically hold a weak reference instead.
	///
	/// (*): libp11 *does* actually do this, by ignoring CKR_CRYPTOKI_ALREADY_INITIALIZED and treating it as success.
	///      It can do this because it never calls C_Finalize anyway and leaves it to the user.
	static ref CONTEXTS: std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, std::sync::Weak<Context>>> = Default::default();
}

/// A context to a PKCS#11 library.
pub struct Context {
	_library: crate::dl::Library,

	pub(crate) C_CloseSession: pkcs11_sys::CK_C_CloseSession,
	pub(crate) C_Encrypt: pkcs11_sys::CK_C_Encrypt,
	pub(crate) C_EncryptInit: pkcs11_sys::CK_C_EncryptInit,
	C_Finalize: Option<pkcs11_sys::CK_C_Finalize>,
	pub(crate) C_FindObjects: pkcs11_sys::CK_C_FindObjects,
	pub(crate) C_FindObjectsFinal: pkcs11_sys::CK_C_FindObjectsFinal,
	pub(crate) C_FindObjectsInit: pkcs11_sys::CK_C_FindObjectsInit,
	pub(crate) C_GenerateKeyPair: pkcs11_sys::CK_C_GenerateKeyPair,
	pub(crate) C_GetAttributeValue: pkcs11_sys::CK_C_GetAttributeValue,
	C_GetSlotList: pkcs11_sys::CK_C_GetSlotList,
	pub(crate) C_GetTokenInfo: pkcs11_sys::CK_C_GetTokenInfo,
	C_GetInfo: Option<pkcs11_sys::CK_C_GetInfo>,
	pub(crate) C_InitPIN: pkcs11_sys::CK_C_InitPIN,
	pub(crate) C_InitToken: pkcs11_sys::CK_C_InitToken,
	pub(crate) C_Login: pkcs11_sys::CK_C_Login,
	pub(crate) C_OpenSession: pkcs11_sys::CK_C_OpenSession,
	pub(crate) C_Sign: pkcs11_sys::CK_C_Sign,
	pub(crate) C_SignInit: pkcs11_sys::CK_C_SignInit,
}

impl Context {
	/// Load the PKCS#11 library at the specified path and create a context.
	pub fn load(lib_path: std::path::PathBuf) -> Result<std::sync::Arc<Self>, LoadContextError> {
		match CONTEXTS.lock().unwrap().entry(lib_path) {
			std::collections::hash_map::Entry::Occupied(mut entry) => {
				let weak = entry.get();
				if let Some(strong) = weak.upgrade() {
					// Loaded this context before, and someone still has a strong reference to it, so we were able to upgrade our weak reference
					// to a new strong reference. Return this new strong reference.
					Ok(strong)
				}
				else {
					// Loaded this context before, but all the strong references to it have been dropped since then.
					// So treat this the same as if we'd never loaded this context before (the Vacant arm below).
					let context = Context::load_inner(entry.key())?;
					let strong = std::sync::Arc::new(context);
					let weak = std::sync::Arc::downgrade(&strong);
					let _ = entry.insert(weak);
					Ok(strong)
				}
			},

			std::collections::hash_map::Entry::Vacant(entry) => {
				// Never tried to load this context before. Load it, store the weak reference, and return the strong reference.
				let context = Context::load_inner(entry.key())?;
				let strong = std::sync::Arc::new(context);
				let weak = std::sync::Arc::downgrade(&strong);
				let _ = entry.insert(weak);
				Ok(strong)
			},
		}
	}

	fn load_inner(lib_path: &std::path::Path) -> Result<Self, LoadContextError> {
		unsafe {
			let library = crate::dl::Library::load(lib_path).map_err(LoadContextError::LoadLibrary)?;

			let C_GetFunctionList: pkcs11_sys::CK_C_GetFunctionList =
				*library.symbol(std::ffi::CStr::from_bytes_with_nul(b"C_GetFunctionList\0").unwrap())
				.map_err(LoadContextError::LoadGetFunctionListSymbol)?;

			let mut function_list = std::ptr::null();
			let result = C_GetFunctionList(&mut function_list);
			if result != pkcs11_sys::CKR_OK {
				return Err(LoadContextError::GetFunctionListFailed(format!("C_GetFunctionList failed with {}", result).into()));
			}
			if function_list.is_null() {
				return Err(LoadContextError::GetFunctionListFailed("C_GetFunctionList succeeded but function list is still NULL".into()));
			}
			let version = (*function_list).version;
			if version.major != 2 || version.minor < 11 {
				// We require 2.20 or higher. However opensc-pkcs11spy self-reports as v2.11 in the initial CK_FUNCTION_LIST version.
				// It does forward the C_GetInfo call down to the underlying PKCS#11 library, so we check the result of that later.
				return Err(LoadContextError::UnsupportedPkcs11Version {
					expected: pkcs11_sys::CK_VERSION { major: 2, minor: 11 },
					actual: version,
				});
			}

			let C_CloseSession = (*function_list).C_CloseSession.ok_or(LoadContextError::MissingFunction("C_CloseSession"))?;
			let C_Encrypt = (*function_list).C_Encrypt.ok_or(LoadContextError::MissingFunction("C_Encrypt"))?;
			let C_EncryptInit = (*function_list).C_EncryptInit.ok_or(LoadContextError::MissingFunction("C_EncryptInit"))?;
			let C_Finalize = (*function_list).C_Finalize;
			let C_FindObjects = (*function_list).C_FindObjects.ok_or(LoadContextError::MissingFunction("C_FindObjects"))?;
			let C_FindObjectsFinal = (*function_list).C_FindObjectsFinal.ok_or(LoadContextError::MissingFunction("C_FindObjectsFinal"))?;
			let C_FindObjectsInit = (*function_list).C_FindObjectsInit.ok_or(LoadContextError::MissingFunction("C_FindObjectsInit"))?;
			let C_GenerateKeyPair = (*function_list).C_GenerateKeyPair.ok_or(LoadContextError::MissingFunction("C_GenerateKeyPair"))?;
			let C_GetAttributeValue = (*function_list).C_GetAttributeValue.ok_or(LoadContextError::MissingFunction("C_GetAttributeValue"))?;
			let C_GetInfo = (*function_list).C_GetInfo;
			let C_GetSlotList = (*function_list).C_GetSlotList.ok_or(LoadContextError::MissingFunction("C_GetSlotList"))?;
			let C_GetTokenInfo = (*function_list).C_GetTokenInfo.ok_or(LoadContextError::MissingFunction("C_GetTokenInfo"))?;
			let C_InitPIN = (*function_list).C_InitPIN.ok_or(LoadContextError::MissingFunction("C_InitPIN"))?;
			let C_InitToken = (*function_list).C_InitToken.ok_or(LoadContextError::MissingFunction("C_InitToken"))?;
			let C_Login = (*function_list).C_Login.ok_or(LoadContextError::MissingFunction("C_Login"))?;
			let C_OpenSession = (*function_list).C_OpenSession.ok_or(LoadContextError::MissingFunction("C_OpenSession"))?;
			let C_Sign = (*function_list).C_Sign.ok_or(LoadContextError::MissingFunction("C_Sign"))?;
			let C_SignInit = (*function_list).C_SignInit.ok_or(LoadContextError::MissingFunction("C_SignInit"))?;

			// Do initialization as the very last thing, so that if it succeeds we're guaranteed to call the corresponding C_Finalize
			let C_Initialize = (*function_list).C_Initialize.ok_or(LoadContextError::MissingFunction("C_Initialize"))?;
			let initialize_args = pkcs11_sys::CK_C_INITIALIZE_ARGS {
				CreateMutex: create_mutex,
				DestroyMutex: destroy_mutex,
				LockMutex: lock_mutex,
				UnlockMutex: unlock_mutex,
				flags: pkcs11_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS,
				pReserved: std::ptr::null_mut(),
			};
			let result = C_Initialize(&initialize_args);
			if result != pkcs11_sys::CKR_OK {
				return Err(LoadContextError::InitializeFailed(result));
			}

			let context = Context {
				_library: library,

				C_CloseSession,
				C_Encrypt,
				C_EncryptInit,
				C_Finalize,
				C_FindObjects,
				C_FindObjectsFinal,
				C_FindObjectsInit,
				C_GenerateKeyPair,
				C_GetAttributeValue,
				C_GetInfo,
				C_GetSlotList,
				C_GetTokenInfo,
				C_InitPIN,
				C_InitToken,
				C_Login,
				C_OpenSession,
				C_Sign,
				C_SignInit,
			};

			let version =
				if let Some(info) = context.info() {
					info.cryptokiVersion
				}
				else {
					// Doesn't support C_GetInfo, so the initial version in the CK_FUNCTION_LIST is all we have.
					version
				};
			if version.major != 2 || version.minor < 20 {
				return Err(LoadContextError::UnsupportedPkcs11Version {
					expected: pkcs11_sys::CK_VERSION { major: 2, minor: 20 },
					actual: version,
				});
			}

			Ok(context)
		}
	}
}

/// An error from loading a PKCS#11 library and creating a context.
#[derive(Debug)]
pub enum LoadContextError {
	LoadGetFunctionListSymbol(String),
	LoadLibrary(String),
	GetFunctionListFailed(std::borrow::Cow<'static, str>),
	InitializeFailed(pkcs11_sys::CK_RV),
	MissingFunction(&'static str),
	UnsupportedPkcs11Version { expected: pkcs11_sys::CK_VERSION, actual: pkcs11_sys::CK_VERSION },
}

impl std::fmt::Display for LoadContextError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LoadContextError::LoadGetFunctionListSymbol(message) => write!(f, "could not load C_GetFunctionList symbol: {}", message),
			LoadContextError::LoadLibrary(message) => write!(f, "could not load library: {}", message),
			LoadContextError::GetFunctionListFailed(message) => write!(f, "could not get function list: {}", message),
			LoadContextError::InitializeFailed(result) => write!(f, "C_Initialize failed with {}", result),
			LoadContextError::MissingFunction(name) => write!(f, "function list is missing required function {}", name),
			LoadContextError::UnsupportedPkcs11Version { expected, actual } =>
				write!(f, "expected library to support {} or higher, but it supports {}", expected, actual),
		}
	}
}

impl std::error::Error for LoadContextError {
}

impl Context {
	/// Get the library's information.
	///
	/// If the library does not support getting its information, this returns `None`.
	pub fn info(&self) -> Option<pkcs11_sys::CK_INFO> {
		unsafe {
			if let Some(C_GetInfo) = self.C_GetInfo {
				let mut info: std::mem::MaybeUninit<pkcs11_sys::CK_INFO> = std::mem::MaybeUninit::uninit();

				let result = C_GetInfo(info.as_mut_ptr());
				if result != pkcs11_sys::CKR_OK {
					return None;
				}

				let info = info.assume_init();
				Some(info)
			}
			else {
				None
			}
		}
	}
}

impl Context {
	/// Get an iterator of slots managed by this library.
	#[allow(clippy::needless_lifetimes)]
	pub fn slots(self: std::sync::Arc<Self>) -> Result<impl Iterator<Item = crate::Slot>, ListSlotsError> {
		// The spec for C_GetSlotList says that it can be used in two ways to get the number of slots:
		//
		// - If the buffer is NULL, `*pulCount` is set to the number of slots, and the call returns `CKR_OK`
		// - If the buffer is not NULL but is too small, `*pulCount` is set to the number of slots, and the call returns `CKR_BUFFER_TOO_SMALL`
		//
		// Since we always have to handle the second case (in case a slot is created between the call with NULL and the call with the actual buffer),
		// we can write a working implementation without needing the first case at all:
		//
		//     let mut slot_ids = vec![];
		//     loop {
		//         let mut actual_len = slot_ids.len();
		//         let result = C_GetSlotList(slot_ids.as_mut_ptr(), &mut actual_len); // Note, always called with a non-NULL buffer.
		//         if result == CKR_OK {
		//             assert!(slot_ids.len() >= actual_len as _);
		//             slot_ids.truncate(actual_len);
		//             return slot_ids;
		//         }
		//         else if result == CKR_BUFFER_TOO_SMALL {
		//             slot_ids = vec![0; actual_len];
		//             continue;
		//         }
		//         else {
		//             return Err(result);
		//         }
		//     }
		//
		// However at least tpm2-pkcs11 does not implement the spec correctly - it does not set `*pulCount` to the number of slots
		// in the second case. See https://github.com/tpm2-software/tpm2-pkcs11/issues/299
		// With such implementations, `actual_len` will never change from 0, and the loop will never terminate.
		//
		// So we *have* to use the first method after all.

		unsafe {
			loop {
				let mut actual_len = 0;
				let result =
					(self.C_GetSlotList)(
						pkcs11_sys::CK_TRUE,
						std::ptr::null_mut(),
						&mut actual_len,
					);
				if result != pkcs11_sys::CKR_OK {
					return Err(ListSlotsError::GetSlotList(result));
				}

				let mut slot_ids = vec![Default::default(); std::convert::TryInto::try_into(actual_len).expect("CK_ULONG -> usize")];

				let result =
					(self.C_GetSlotList)(
						pkcs11_sys::CK_TRUE,
						slot_ids.as_mut_ptr(),
						&mut actual_len,
					);
				match result {
					pkcs11_sys::CKR_OK => {
						let actual_len = std::convert::TryInto::try_into(actual_len).expect("CK_ULONG -> usize");

						// If slot_ids.len() < actual_len, then the PKCS#11 library has scribbled past the end of the buffer.
						// This is not safe to recover from.
						//
						// Vec::truncate silently ignores a request to truncate to longer than its current length,
						// so we must check for it ourselves.
						assert!(slot_ids.len() >= actual_len);

						slot_ids.truncate(actual_len);

						return Ok(slot_ids.into_iter().map(move |id| crate::Slot::new(self.clone(), id)));
					},

					pkcs11_sys::CKR_BUFFER_TOO_SMALL => {
						// New slot created between the first and second calls to C_GetSlotList. Try again.
					},

					result => return Err(ListSlotsError::GetSlotList(result)),
				}
			}
		}
	}
}

/// An error from get a token's info.
#[derive(Debug)]
pub enum ListSlotsError {
	GetSlotList(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for ListSlotsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ListSlotsError::GetSlotList(result) => write!(f, "C_GetSlotList failed with {}", result),
		}
	}
}

impl std::error::Error for ListSlotsError {
}

impl Context {
	/// Get a reference to a slot managed by this library.
	///
	/// Note that this API does not prevent you at the typesystem-level from attempting to open multiple read-write sessions against the same slot.
	/// It will only fail at runtime.
	#[allow(clippy::needless_lifetimes)]
	pub fn slot(self: std::sync::Arc<Self>, id: pkcs11_sys::CK_SLOT_ID) -> crate::Slot {
		crate::Slot::new(self, id)
	}
}

impl Drop for Context {
	fn drop(&mut self) {
		unsafe {
			if let Some(C_Finalize) = self.C_Finalize {
				let _ = C_Finalize(std::ptr::null_mut());
			}
		}
	}
}

unsafe impl Send for Context { }
unsafe impl Sync for Context { }

/// A PKCS#11 mutex implementation using a [`std::sync::Mutex`]
#[repr(C)]
struct Mutex {
	inner: std::sync::Mutex<()>,
	guard: Option<std::sync::MutexGuard<'static, ()>>,
}

unsafe extern "C" fn create_mutex(ppMutex: pkcs11_sys::CK_VOID_PTR_PTR) -> pkcs11_sys::CK_RV {
	let mutex = Mutex {
		inner: Default::default(),
		guard: None,
	};
	let mutex = Box::new(mutex);
	let mutex = Box::into_raw(mutex);
	*ppMutex = mutex as _;
	pkcs11_sys::CKR_OK
}

unsafe extern "C" fn destroy_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
	if pMutex.is_null() {
		return pkcs11_sys::CKR_MUTEX_BAD;
	}

	let mut mutex: Box<Mutex> = Box::from_raw(pMutex as _);
	drop(mutex.guard.take());
	drop(mutex);
	pkcs11_sys::CKR_OK
}

unsafe extern "C" fn lock_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
	if pMutex.is_null() {
		return pkcs11_sys::CKR_MUTEX_BAD;
	}

	let mutex: &mut Mutex = &mut *(pMutex as *mut _);
	let guard = match mutex.inner.lock() {
		Ok(guard) => guard,
		Err(_) => return pkcs11_sys::CKR_GENERAL_ERROR,
	};
	let guard = std::mem::transmute(guard);
	mutex.guard = guard;
	pkcs11_sys::CKR_OK
}

unsafe extern "C" fn unlock_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
	if pMutex.is_null() {
		return pkcs11_sys::CKR_MUTEX_BAD;
	}

	let mutex: &mut Mutex = &mut *(pMutex as *mut _);
	if mutex.guard.take().is_none() {
		return pkcs11_sys::CKR_MUTEX_NOT_LOCKED;
	}
	pkcs11_sys::CKR_OK
}
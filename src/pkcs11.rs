#![allow(non_snake_case)]

use crate::pkcs11_sys;

/// A context to a PKCS#11 library.
pub(crate) struct Context {
	_library: crate::dl::Library,

	C_CloseSession: pkcs11_sys::CK_C_CloseSession,
	C_Finalize: Option<pkcs11_sys::CK_C_Finalize>,
	C_GenerateKeyPair: pkcs11_sys::CK_C_GenerateKeyPair,
	C_GetAttributeValue: pkcs11_sys::CK_C_GetAttributeValue,
	C_GetSlotList: pkcs11_sys::CK_C_GetSlotList,
	C_GetTokenInfo: pkcs11_sys::CK_C_GetTokenInfo,
	C_GetInfo: Option<pkcs11_sys::CK_C_GetInfo>,
	C_InitPIN: pkcs11_sys::CK_C_InitPIN,
	C_InitToken: pkcs11_sys::CK_C_InitToken,
	C_Login: pkcs11_sys::CK_C_Login,
	C_Logout: pkcs11_sys::CK_C_Logout,
	C_OpenSession: pkcs11_sys::CK_C_OpenSession,
}

impl Context {
	/// Load the PKCS#11 library at the specified path and create a context.
	pub(crate) fn load(lib_path: &std::path::Path) -> Result<Self, LoadContextError> {
		unsafe {
			let library = crate::dl::Library::load(lib_path).map_err(LoadContextError::LoadLibrary)?;

			let C_GetFunctionList: pkcs11_sys::CK_C_GetFunctionList =
				*library.symbol(std::ffi::CStr::from_bytes_with_nul(b"C_GetFunctionList\0").unwrap())
				.map_err(LoadContextError::LoadGetFunctionListSymbol)?;

			let mut function_list = std::ptr::null_mut();
			let result = C_GetFunctionList(&mut function_list);
			if result != pkcs11_sys::CKR_OK {
				return Err(LoadContextError::GetFunctionListFailed(format!("C_GetFunctionList failed with {}", result).into()));
			}
			if function_list.is_null() {
				return Err(LoadContextError::GetFunctionListFailed("C_GetFunctionList succeeded but function list is still NULL".into()));
			}
			let version = (*function_list).version;
			if version.major != 2 || version.minor < 40 {
				return Err(LoadContextError::UnsupportedPkcs11Version(version));
			}

			let C_CloseSession = (*function_list).C_CloseSession.ok_or(LoadContextError::MissingFunction("C_CloseSession"))?;
			let C_Finalize = (*function_list).C_Finalize;
			let C_GenerateKeyPair = (*function_list).C_GenerateKeyPair.ok_or(LoadContextError::MissingFunction("C_GenerateKeyPair"))?;
			let C_GetAttributeValue = (*function_list).C_GetAttributeValue.ok_or(LoadContextError::MissingFunction("C_GetAttributeValue"))?;
			let C_GetInfo = (*function_list).C_GetInfo;
			let C_GetSlotList = (*function_list).C_GetSlotList.ok_or(LoadContextError::MissingFunction("C_GetSlotList"))?;
			let C_GetTokenInfo = (*function_list).C_GetTokenInfo.ok_or(LoadContextError::MissingFunction("C_GetTokenInfo"))?;
			let C_InitPIN = (*function_list).C_InitPIN.ok_or(LoadContextError::MissingFunction("C_InitPIN"))?;
			let C_InitToken = (*function_list).C_InitToken.ok_or(LoadContextError::MissingFunction("C_InitToken"))?;
			let C_Login = (*function_list).C_Login.ok_or(LoadContextError::MissingFunction("C_Login"))?;
			let C_Logout = (*function_list).C_Logout.ok_or(LoadContextError::MissingFunction("C_Logout"))?;
			let C_OpenSession = (*function_list).C_OpenSession.ok_or(LoadContextError::MissingFunction("C_OpenSession"))?;

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

			Ok(Context {
				_library: library,

				C_CloseSession,
				C_Finalize,
				C_GenerateKeyPair,
				C_GetAttributeValue,
				C_GetInfo,
				C_GetSlotList,
				C_GetTokenInfo,
				C_InitPIN,
				C_InitToken,
				C_Login,
				C_Logout,
				C_OpenSession,
			})
		}
	}
}

/// An error from loading a PKCS#11 library and creating a context.
#[derive(Debug)]
pub(crate) enum LoadContextError {
	LoadGetFunctionListSymbol(String),
	LoadLibrary(String),
	GetFunctionListFailed(std::borrow::Cow<'static, str>),
	InitializeFailed(pkcs11_sys::CK_RV),
	MissingFunction(&'static str),
	UnsupportedPkcs11Version(pkcs11_sys::CK_VERSION),
}

impl std::fmt::Display for LoadContextError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LoadContextError::LoadGetFunctionListSymbol(message) => write!(f, "could not load C_GetFunctionList symbol: {}", message),
			LoadContextError::LoadLibrary(message) => write!(f, "could not load library: {}", message),
			LoadContextError::GetFunctionListFailed(message) => write!(f, "could not get function list: {}", message),
			LoadContextError::InitializeFailed(result) => write!(f, "C_Initialize failed with {}", result),
			LoadContextError::MissingFunction(name) => write!(f, "function list is missing required function {}", name),
			LoadContextError::UnsupportedPkcs11Version(version) => write!(f, "expected library to support v2.40 or higher, but it supports {}", version),
		}
	}
}

impl std::error::Error for LoadContextError {
}

impl Context {
	/// Get the library's information.
	///
	/// If the library does not support getting its information, this returns `None`.
	pub(crate) fn info(&self) -> Option<pkcs11_sys::CK_INFO> {
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
	pub(crate) fn slots<'slot>(&'slot self) -> Result<impl Iterator<Item = Slot<'slot>> + 'slot, ListSlotsError> {
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

				let mut slot_ids = vec![Default::default(); actual_len as _];

				let result =
					(self.C_GetSlotList)(
						pkcs11_sys::CK_TRUE,
						slot_ids.as_mut_ptr(),
						&mut actual_len,
					);
				match result {
					pkcs11_sys::CKR_OK => {
						// If slot_ids.len() < actual_len, then the PKCS#11 library has scribbled past the end of the buffer.
						// This is not safe to recover from.
						//
						// Vec::truncate silently ignores a request to truncate to longer than its current length,
						// so we must check for it ourselves.
						assert!(slot_ids.len() >= actual_len as _);

						slot_ids.truncate(actual_len as _);

						return Ok(slot_ids.into_iter().map(move |id| Slot { context: self, id }));
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
pub(crate) enum ListSlotsError {
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
	pub(crate) fn slot<'slot>(&'slot self, id: pkcs11_sys::CK_SLOT_ID) -> Slot<'slot> {
		Slot {
			context: self,
			id,
		}
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

/// A reference to a single slot managed by the parent PKCS#11 library.
pub(crate) struct Slot<'slot> {
	context: &'slot Context,
	id: pkcs11_sys::CK_SLOT_ID,
}

impl<'slot> Slot<'slot> {
	/// Get the info of the token in this slot.
	pub(crate) fn token_info(&self) -> Result<pkcs11_sys::CK_TOKEN_INFO, GetTokenInfoError> {
		unsafe {
			let mut info: std::mem::MaybeUninit<pkcs11_sys::CK_TOKEN_INFO> = std::mem::MaybeUninit::uninit();

			let result =
				(self.context.C_GetTokenInfo)(
					self.id,
					info.as_mut_ptr(),
				);
			if result != pkcs11_sys::CKR_OK {
				return Err(GetTokenInfoError::GetTokenInfo(result));
			}

			let info = info.assume_init();
			Ok(info)
		}
	}
}

/// An error from get a token's info.
#[derive(Debug)]
pub(crate) enum GetTokenInfoError {
	GetTokenInfo(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for GetTokenInfoError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			GetTokenInfoError::GetTokenInfo(result) => write!(f, "C_GetTokenInfo failed with {}", result),
		}
	}
}

impl std::error::Error for GetTokenInfoError {
}

impl<'slot> Slot<'slot> {
	/// Initialize the slot with the given label, SO PIN and user PIN.
	///
	/// If the slot was already initialized, it will be reinitialized. In this case the SO PIN must match what was originally set on the slot.
	pub(crate) fn initialize(&mut self, label: std::borrow::Cow<'_, str>, so_pin: &str, user_pin: &str) -> Result<(), InitializeSlotError> {
		unsafe {
			let label = pad_32(label).map_err(|()| InitializeSlotError::LabelTooLong)?;

			let result =
				(self.context.C_InitToken)(
					self.id,
					so_pin.as_ptr() as _,
					so_pin.len() as _,
					label.as_ptr(),
				);
			if result != pkcs11_sys::CKR_OK {
				return Err(InitializeSlotError::InitializeToken(result));
			}

			let session =
				self.open_session_inner(
					true,
					pkcs11_sys::CKU_SO,
					so_pin,
				).map_err(InitializeSlotError::OpenSOSession)?;

			let result =
				(self.context.C_InitPIN)(
					session.handle,
					user_pin.as_ptr() as _,
					user_pin.len() as _,
				);
			if result != pkcs11_sys::CKR_OK {
				return Err(InitializeSlotError::InitializeUserPin(result));
			}

			Ok(())
		}
	}
}

/// An error from loading a PKCS#11 library and creating a context.
#[derive(Debug)]
pub(crate) enum InitializeSlotError {
	InitializeToken(pkcs11_sys::CK_RV),
	InitializeUserPin(pkcs11_sys::CK_RV),
	LabelTooLong,
	OpenSOSession(OpenSessionError),
}

impl std::fmt::Display for InitializeSlotError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			InitializeSlotError::InitializeToken(result) => write!(f, "C_InitToken failed with {}", result),
			InitializeSlotError::InitializeUserPin(result) => write!(f, "C_InitPIN for the user PIN failed with {}", result),
			InitializeSlotError::LabelTooLong => write!(f, "label must be 32 bytes or less"),
			InitializeSlotError::OpenSOSession(_) => write!(f, "could not open SO session"),
		}
	}
}

impl std::error::Error for InitializeSlotError {
	#[allow(clippy::match_same_arms)]
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			InitializeSlotError::InitializeToken(_) => None,
			InitializeSlotError::InitializeUserPin(_) => None,
			InitializeSlotError::LabelTooLong => None,
			InitializeSlotError::OpenSOSession(inner) => Some(inner),
		}
	}
}

impl<'slot> Slot<'slot> {
	pub(crate) fn open_session<'session>(&'session self, read_write: bool, pin: &str) -> Result<Session<'session>, OpenSessionError> {
		unsafe {
			self.open_session_inner(
				read_write,
				pkcs11_sys::CKU_USER,
				pin,
			)
		}
	}

	unsafe fn open_session_inner<'session>(
		&'session self,
		read_write: bool,
		user_type: pkcs11_sys::CK_USER_TYPE,
		pin: &str,
	) -> Result<Session<'session>, OpenSessionError> {
		let mut flags = pkcs11_sys::CKF_SERIAL_SESSION;
		if read_write {
			flags |= pkcs11_sys::CKF_RW_SESSION;
		}

		let mut handle = pkcs11_sys::CK_INVALID_SESSION_HANDLE;
		let result =
			(self.context.C_OpenSession)(
				self.id,
				flags,
				std::ptr::null_mut(),
				None,
				&mut handle,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(OpenSessionError::OpenSessionFailed(format!("C_OpenSession failed with {}", result).into()));
		}
		if handle == pkcs11_sys::CK_INVALID_SESSION_HANDLE {
			return Err(OpenSessionError::OpenSessionFailed("C_OpenSession succeeded but session handle is still CK_INVALID_HANDLE".into()));
		}
		let session = Session {
			slot: self,
			handle,
		};

		let result =
			(self.context.C_Login)(
				session.handle,
				user_type,
				pin.as_ptr() as _,
				pin.len() as _,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(OpenSessionError::LoginFailed(result));
		}

		Ok(session)
	}
}

/// An error from opening a session against a slot.
#[derive(Debug)]
pub(crate) enum OpenSessionError {
	OpenSessionFailed(std::borrow::Cow<'static, str>),
	LoginFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for OpenSessionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			OpenSessionError::OpenSessionFailed(message) => write!(f, "could not open session: {}", message),
			OpenSessionError::LoginFailed(result) => write!(f, "C_Login for the user PIN failed with {}", result),
		}
	}
}

impl std::error::Error for OpenSessionError {
}

pub(crate) struct Session<'session> {
	slot: &'session Slot<'session>,
	handle: pkcs11_sys::CK_SESSION_HANDLE,
}

impl<'session> Session<'session> {
	pub(crate) fn generate_ec_key_pair(
		&'session self,
		curve: EcCurve,
	) -> Result<(Object<'session, openssl::ec::EcKey<openssl::pkey::Public>>, Object<'session, openssl::ec::EcKey<openssl::pkey::Private>>), GenerateKeyPairError> {
		unsafe {
			let oid = curve.as_oid_der();

			let public_key_template = vec![
				pkcs11_sys::CK_ATTRIBUTE_IN {
					r#type: pkcs11_sys::CKA_EC_PARAMS,
					pValue: oid.as_ptr() as _,
					ulValueLen: oid.len() as _,
				},
			];

			let private_key_template = vec![];

			self.generate_key_pair_inner(
				pkcs11_sys::CKM_EC_KEY_PAIR_GEN,
				public_key_template,
				private_key_template,
			)
		}
	}

	pub(crate) fn generate_rsa_key_pair(
		&'session self,
		modulus_bits: pkcs11_sys::CK_ULONG,
		exponent: &openssl::bn::BigNum,
	) -> Result<(Object<'session, openssl::rsa::Rsa<openssl::pkey::Public>>, Object<'session, openssl::rsa::Rsa<openssl::pkey::Private>>), GenerateKeyPairError> {
		unsafe {
			let exponent = exponent.to_vec();

			let public_key_template = vec![
				pkcs11_sys::CK_ATTRIBUTE_IN {
					r#type: pkcs11_sys::CKA_MODULUS_BITS,
					pValue: &modulus_bits as *const _ as _,
					ulValueLen: std::mem::size_of_val(&modulus_bits) as _,
				},
				pkcs11_sys::CK_ATTRIBUTE_IN {
					r#type: pkcs11_sys::CKA_PUBLIC_EXPONENT,
					pValue: exponent.as_ptr() as _,
					ulValueLen: exponent.len() as _,
				},
			];

			let private_key_template = vec![];

			self.generate_key_pair_inner(
				pkcs11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
				public_key_template,
				private_key_template,
			)
		}
	}

	unsafe fn generate_key_pair_inner<TPublic, TPrivate>(
		&'session self,
		mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
		mut public_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
		mut private_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
	) -> Result<(Object<'session, TPublic>, Object<'session, TPrivate>), GenerateKeyPairError> {
		let mechanism = pkcs11_sys::CK_MECHANISM_IN {
			mechanism,
			pParameter: std::ptr::null(),
			ulParameterLen: 0,
		};

		let r#true = pkcs11_sys::CK_TRUE;
		let true_size = std::mem::size_of_val(&r#true) as _;
		let r#true = &r#true as *const _ as _;

		// The spec's example also passes in CKA_WRAP for the public key and CKA_UNWRAP for the private key,
		// but tpm2-pkcs11's impl of `C_GenerateKeyPair` does not recognize those and fails.
		//
		// We don't need them anyway, so we don't pass them.

		public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_ENCRYPT,
			pValue: r#true,
			ulValueLen: true_size,
		});
		public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_TOKEN,
			pValue: r#true,
			ulValueLen: true_size,
		});
		public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_VERIFY,
			pValue: r#true,
			ulValueLen: true_size,
		});

		private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_DECRYPT,
			pValue: r#true,
			ulValueLen: true_size,
		});
		private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_PRIVATE,
			pValue: r#true,
			ulValueLen: true_size,
		});
		private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_SENSITIVE,
			pValue: r#true,
			ulValueLen: true_size,
		});
		private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_SIGN,
			pValue: r#true,
			ulValueLen: true_size,
		});
		private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_TOKEN,
			pValue: r#true,
			ulValueLen: true_size,
		});

		let mut public_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
		let mut private_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;

		let result =
			(self.slot.context.C_GenerateKeyPair)(
				self.handle,
				&mechanism,
				public_key_template.as_ptr() as _,
				public_key_template.len() as _,
				private_key_template.as_ptr() as _,
				private_key_template.len() as _,
				&mut public_key_handle,
				&mut private_key_handle,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(GenerateKeyPairError::GenerateKeyPairFailed(format!("C_GenerateKeyPair failed with {}", result).into()));
		}
		if public_key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
			return Err(GenerateKeyPairError::GenerateKeyPairFailed("C_GenerateKeyPair succeeded but public key handle is still CK_INVALID_HANDLE".into()));
		}
		if private_key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
			return Err(GenerateKeyPairError::GenerateKeyPairFailed("C_GenerateKeyPair succeeded but private key handle is still CK_INVALID_HANDLE".into()));
		}

		Ok((
			Object {
				session: self,
				handle: public_key_handle,
				_key: Default::default(),
			},
			Object {
				session: self,
				handle: private_key_handle,
				_key: Default::default(),
			},
		))
	}
}

/// An error from generating a key pair.
#[derive(Debug)]
pub(crate) enum GenerateKeyPairError {
	GenerateKeyPairFailed(std::borrow::Cow<'static, str>),
}

impl std::fmt::Display for GenerateKeyPairError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			GenerateKeyPairError::GenerateKeyPairFailed(message) => write!(f, "could not generate key pair: {}", message),
		}
	}
}

impl std::error::Error for GenerateKeyPairError {
}

impl<'session> Drop for Session<'session> {
	fn drop(&mut self) {
		unsafe {
			let _ = (self.slot.context.C_Logout)(self.handle);
			let _ = (self.slot.context.C_CloseSession)(self.handle);
		}
	}
}

/// A reference to an object stored in a slot.
pub(crate) struct Object<'session, T> {
	session: &'session Session<'session>,
	handle: pkcs11_sys::CK_OBJECT_HANDLE,
	_key: std::marker::PhantomData<T>,
}

impl<'session> Object<'session, openssl::ec::EcKey<openssl::pkey::Public>> {
	/// Get the EC parameters of this EC public key object.
	pub(crate) fn parameters(&self) -> Result<openssl::ec::EcKey<openssl::pkey::Public>, GetKeyParametersError> {
		unsafe {
			let curve = get_attribute_value_byte_buf(
				self.session,
				self,
				pkcs11_sys::CKA_EC_PARAMS,
				self.session.slot.context.C_GetAttributeValue,
			)?;
			let curve = EcCurve::from_oid_der(&curve).ok_or_else(|| GetKeyParametersError::UnrecognizedEcCurve(curve))?;
			let curve = curve.as_nid();
			let group = openssl::ec::EcGroup::from_curve_name(curve).map_err(GetKeyParametersError::ConvertToOpenssl)?;

			// CKA_EC_POINT returns a DER encoded octet string representing the point.
			//
			// The octet string is in the RFC 5480 format which is exactly what EC_POINT_oct2point expected, so we just need to strip the DER type and length prefix.
			let point = get_attribute_value_byte_buf(
				self.session,
				self,
				pkcs11_sys::CKA_EC_POINT,
				self.session.slot.context.C_GetAttributeValue,
			)?;
			let point =
				crate::openssl_sys2::d2i_ASN1_OCTET_STRING(
					std::ptr::null_mut(),
					&mut (point.as_ptr() as _),
					point.len() as _,
				);
			if point.is_null() {
				return Err(GetKeyParametersError::MalformedEcPoint(openssl::error::ErrorStack::get()));
			}
			let point: openssl::asn1::Asn1String = foreign_types::ForeignType::from_ptr(point);
			let mut big_num_context = openssl::bn::BigNumContext::new().map_err(GetKeyParametersError::ConvertToOpenssl)?;
			let point = openssl::ec::EcPoint::from_bytes(&group, point.as_slice(), &mut big_num_context).map_err(GetKeyParametersError::ConvertToOpenssl)?;

			let parameters = openssl::ec::EcKey::<openssl::pkey::Public>::from_public_key(
				&group,
				&point,
			).map_err(GetKeyParametersError::ConvertToOpenssl)?;
			Ok(parameters)
		}
	}
}

impl<'session> Object<'session, openssl::rsa::Rsa<openssl::pkey::Public>> {
	/// Get the RSA parameters of this RSA public key object.
	pub(crate) fn parameters(&self) -> Result<openssl::rsa::Rsa<openssl::pkey::Public>, GetKeyParametersError> {
		unsafe {
			let modulus = get_attribute_value_byte_buf(
				self.session,
				self,
				pkcs11_sys::CKA_MODULUS,
				self.session.slot.context.C_GetAttributeValue,
			)?;
			let modulus = openssl::bn::BigNum::from_slice(&modulus).map_err(GetKeyParametersError::ConvertToOpenssl)?;

			let public_exponent = get_attribute_value_byte_buf(
				self.session,
				self,
				pkcs11_sys::CKA_PUBLIC_EXPONENT,
				self.session.slot.context.C_GetAttributeValue,
			)?;
			let public_exponent = openssl::bn::BigNum::from_slice(&public_exponent).map_err(GetKeyParametersError::ConvertToOpenssl)?;

			let parameters = openssl::rsa::Rsa::<openssl::pkey::Public>::from_public_components(
				modulus,
				public_exponent,
			).map_err(GetKeyParametersError::ConvertToOpenssl)?;
			Ok(parameters)
		}
	}
}

/// An error from getting the parameters of a key object.
#[derive(Debug)]
pub(crate) enum GetKeyParametersError {
	ConvertToOpenssl(openssl::error::ErrorStack),
	GetAttributeValueFailed(pkcs11_sys::CK_RV),
	MalformedEcPoint(openssl::error::ErrorStack),
	UnrecognizedEcCurve(Vec<u8>),
}

impl std::fmt::Display for GetKeyParametersError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			GetKeyParametersError::ConvertToOpenssl(_) => write!(f, "could not convert components to openssl types"),
			GetKeyParametersError::GetAttributeValueFailed(result) => write!(f, "C_GetAttributeValue failed with {}", result),
			GetKeyParametersError::MalformedEcPoint(_) => write!(f, "could not parse the DER-encoded EC point"),
			GetKeyParametersError::UnrecognizedEcCurve(curve) => write!(f, "the EC point is using an unknown curve: {:?}", curve),
		}
	}
}

impl std::error::Error for GetKeyParametersError {
	#[allow(clippy::match_same_arms)]
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			GetKeyParametersError::ConvertToOpenssl(inner) => Some(inner),
			GetKeyParametersError::GetAttributeValueFailed(_) => None,
			GetKeyParametersError::MalformedEcPoint(inner) => Some(inner),
			GetKeyParametersError::UnrecognizedEcCurve(_) => None,
		}
	}
}

/// The kinds of EC curves supported for key generation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EcCurve {
	/// ed25519
	///
	/// Note: Requires openssl >= 1.1.1
	///
	/// Note: This has not been tested since softhsm does not support it, which in turn is because openssl (as of v1.1.1c) does not support it
	/// for key generation.
	#[cfg(ed25519)]
	Ed25519,

	/// secp256r1, known to openssl as prime256v1
	NistP256,

	/// secp384r1
	NistP384,

	/// secp521r1
	NistP521,
}

impl EcCurve {
	#[cfg(ed25519)]
	const ED25519_OID_DER: &'static [u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
	const SECP256R1_OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
	const SECP384R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
	const SECP521R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

	fn as_nid(self) -> openssl::nid::Nid {
		match self {
			#[cfg(ed25519)]
			EcCurve::Ed25519 => openssl::nid::Nid::from_raw(openssl_sys::NID_ED25519), // Not wrapped by openssl as of v0.10.25
			EcCurve::NistP256 => openssl::nid::Nid::X9_62_PRIME256V1,
			EcCurve::NistP384 => openssl::nid::Nid::SECP384R1,
			EcCurve::NistP521 => openssl::nid::Nid::SECP521R1,
		}
	}

	fn as_oid_der(self) -> &'static [u8] {
		match self {
			#[cfg(ed25519)]
			EcCurve::Ed25519 => EcCurve::ED25519_OID_DER,
			EcCurve::NistP256 => EcCurve::SECP256R1_OID_DER,
			EcCurve::NistP384 => EcCurve::SECP384R1_OID_DER,
			EcCurve::NistP521 => EcCurve::SECP521R1_OID_DER,
		}
	}

	fn from_oid_der(oid: &[u8]) -> Option<Self> {
		match oid {
			#[cfg(ed25519)]
			EcCurve::ED25519_OID_DER => Some(EcCurve::Ed25519),
			EcCurve::SECP256R1_OID_DER => Some(EcCurve::NistP256),
			EcCurve::SECP384R1_OID_DER => Some(EcCurve::NistP384),
			EcCurve::SECP521R1_OID_DER => Some(EcCurve::NistP521),
			_ => None,
		}
	}
}

#[derive(Debug, PartialEq)]
pub(crate) struct Uri {
	pub(crate) slot_identifier: UriSlotIdentifier,
	pub(crate) pin: String,
}

#[derive(Debug, PartialEq)]
pub(crate) enum UriSlotIdentifier {
	Label(String),
	SlotId(pkcs11_sys::CK_SLOT_ID),
}

impl std::str::FromStr for Uri {
	type Err = ParsePkcs11UriError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		// Ref https://tools.ietf.org/html/rfc7512#section-2.3
		//
		// Only slot-id, token and pin-value are parsed from the URL. If both slot-id and token are provided, token is ignored.

		enum PathComponentKey {
			SlotId,
			Token,
		}

		enum QueryComponentKey {
			PinValue,
		}

		fn parse_key_value_pair<'a, F, T>(
			s: &'a str,
			mut key_discriminant: F,
		) -> Result<Option<(T, std::borrow::Cow<'a, str>)>, ParsePkcs11UriError> where F: FnMut(&[u8]) -> Option<T> {
			let mut parts = s.splitn(2, '=');

			let key = parts.next().expect("str::splitn() yields at least one str");
			let key = percent_encoding::percent_decode(key.as_bytes());
			let key: std::borrow::Cow<'a, _> = key.into();
			if let Some(typed_key) = key_discriminant(&*key) {
				let value = parts.next().unwrap_or_default();
				let value = percent_encoding::percent_decode(value.as_bytes());
				match value.decode_utf8() {
					Ok(value) => Ok(Some((typed_key, value))),
					Err(err) => Err(ParsePkcs11UriError::InvalidUtf8(key.into_owned(), err.into())),
				}
			}
			else {
				Ok(None)
			}
		}

		let mut label = None;
		let mut slot_id = None;
		let mut pin = None;

		let s =
			if s.starts_with("pkcs11:") {
				&s[("pkcs11:".len())..]
			}
			else {
				return Err(ParsePkcs11UriError::InvalidScheme);
			};

		let mut url_parts = s.split('?');

		let path = url_parts.next().expect("str::split() yields at least one str");
		let path_components = path.split(';');
		for path_component in path_components {
			let key_value_pair = parse_key_value_pair(path_component, |key| match key {
				b"slot-id" => Some(PathComponentKey::SlotId),
				b"token" => Some(PathComponentKey::Token),
				_ => None,
			})?;
			if let Some((key, value)) = key_value_pair {
				match key {
					PathComponentKey::SlotId => {
						let value = value.parse::<pkcs11_sys::CK_SLOT_ID>().map_err(|err| ParsePkcs11UriError::MalformedSlotId(value.into_owned(), err))?;
						slot_id = Some(value);
					},
					PathComponentKey::Token => {
						label = Some(value.into_owned());
					},
				}
			}
		}

		let query = url_parts.next().unwrap_or_default();
		let query_components = query.split('&');
		for query_component in query_components {
			let key_value_pair = parse_key_value_pair(query_component, |key| match key {
				b"pin-value" => Some(QueryComponentKey::PinValue),
				_ => None,
			})?;
			if let Some((key, value)) = key_value_pair {
				match key {
					QueryComponentKey::PinValue => {
						pin = Some(value.into_owned());
					},
				}
			}
		}

		let slot_identifier = match (label, slot_id) {
			(_, Some(slot_id)) => UriSlotIdentifier::SlotId(slot_id),
			(Some(label), _) => UriSlotIdentifier::Label(label.to_owned()),
			(None, None) => return Err(ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified),
		};

		let pin = pin.unwrap_or_default();

		Ok(Uri {
			slot_identifier,
			pin,
		})
	}
}

#[derive(Debug)]
pub(crate) enum ParsePkcs11UriError {
	InvalidScheme,
	InvalidUtf8(Vec<u8>, Box<dyn std::error::Error>),
	MalformedSlotId(String, <pkcs11_sys::CK_SLOT_ID as std::str::FromStr>::Err),
	NeitherSlotIdNorTokenSpecified,
}

impl std::fmt::Display for ParsePkcs11UriError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ParsePkcs11UriError::InvalidScheme => f.write_str("URI does not have pkcs11 scheme"),
			ParsePkcs11UriError::InvalidUtf8(key, _) => write!(f, "URI component with key [{:?}] is not valid UTF-8", key),
			ParsePkcs11UriError::MalformedSlotId(value, _) => write!(f, "pin-value path component has malformed value [{}]", value),
			ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified => f.write_str("URI has neither [slot-id] nor [token] components"),
		}
	}
}

impl std::error::Error for ParsePkcs11UriError {
	#[allow(clippy::match_same_arms)]
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			ParsePkcs11UriError::InvalidScheme => None,
			ParsePkcs11UriError::InvalidUtf8(_, inner) => Some(&**inner),
			ParsePkcs11UriError::MalformedSlotId(_, inner) => Some(inner),
			ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified => None,
		}
	}
}

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

	let mutex: Box<Mutex> = Box::from_raw(pMutex as _);
	assert!(mutex.guard.is_none());
	let _ = mutex;
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

/// Pad the given string to 32 bytes. Fails if the string is longer than 32 bytes.
#[allow(clippy::needless_lifetimes)]
fn pad_32<'a>(s: std::borrow::Cow<'a, str>) -> Result<std::borrow::Cow<'a, str>, ()> {
	match s.len() {
		len if len == 32 => Ok(s),
		len if len < 32 => Ok(format!("{:length$}", s, length = 32 - s.len() + s.chars().count()).into()),
		_ => Err(()),
	}
}

/// Query an attribute value as a byte buffer of arbitrary length.
unsafe fn get_attribute_value_byte_buf<T>(
	session: &Session<'_>,
	object: &Object<'_, T>,
	r#type: pkcs11_sys::CK_ATTRIBUTE_TYPE,
	C_GetAttributeValue: pkcs11_sys::CK_C_GetAttributeValue,
) -> Result<Vec<u8>, GetKeyParametersError> {
	// Per the docs of C_GetAttributeValue, it is legal to call it with pValue == NULL and ulValueLen == 0.
	// In this case it will set ulValueLen to the size of buffer it needs and return CKR_OK.

	let mut attribute = pkcs11_sys::CK_ATTRIBUTE {
		r#type,
		pValue: std::ptr::null_mut(),
		ulValueLen: 0,
	};

	let result =
		C_GetAttributeValue(
			session.handle,
			object.handle,
			&mut attribute,
			1,
		);
	if result != pkcs11_sys::CKR_OK {
		return Err(GetKeyParametersError::GetAttributeValueFailed(result));
	}

	let mut buf = vec![0_u8; std::convert::TryInto::try_into(attribute.ulValueLen).expect("c_ulong is larger than usize")];
	attribute.pValue = buf.as_mut_ptr() as _;

	let result =
		C_GetAttributeValue(
			session.handle,
			object.handle,
			&mut attribute,
			1,
		);
	if result != pkcs11_sys::CKR_OK {
		return Err(GetKeyParametersError::GetAttributeValueFailed(result));
	}

	Ok(buf)
}

#[cfg(test)]
mod tests {
	#[test]
	fn parse_pkcs11_uri() {
		assert_eq!(
			"pkcs11:slot-id=1?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::SlotId(crate::pkcs11_sys::CK_SLOT_ID(1)),
				pin: "1234".to_owned(),
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: "1234".to_owned(),
			},
		);

		assert_eq!(
			"pkcs11:slot-id=1;token=Foo%20Bar?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::SlotId(crate::pkcs11_sys::CK_SLOT_ID(1)),
				pin: "1234".to_owned(),
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: String::new(),
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar;foo=bar?baz=quux&pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: "1234".to_owned(),
			},
		);

		let _ = "kcs11:token=Foo%20Bar".parse::<super::Uri>().expect_err("expect URI with invalid scheme to fail to parse");

		let _ = "pkcs11:".parse::<super::Uri>().expect_err("expect URI with neither label nor slot ID to fail to parse");
	}

	#[test]
	fn pad_32() {
		// 4 codepoints taking 4 bytes should be padded with 28 spaces
		assert_eq!(super::pad_32("1234".into()).unwrap(), "1234                            ");

		// 2 codepoints taking 6 bytes should be padded with 26 spaces
		assert_eq!(super::pad_32("日本".into()).unwrap(), "日本                          ");

		// Max length
		assert_eq!(super::pad_32("12345678901234567890123456789012".into()).unwrap(), "12345678901234567890123456789012");
		assert_eq!(super::pad_32("1日本日本日本日本日本2".into()).unwrap(), "1日本日本日本日本日本2");

		// Too long
		assert!(super::pad_32("123456789012345678901234567890123".into()).is_err());
		assert!(super::pad_32("日本日本日本日本日本日本".into()).is_err());
	}
}

/// A reference to a single slot managed by the parent PKCS#11 library.
pub struct Slot {
	context: std::sync::Arc<crate::Context>,
	id: pkcs11_sys::CK_SLOT_ID,
}

impl Slot {
	pub(crate) fn new(context: std::sync::Arc<crate::Context>, id: pkcs11_sys::CK_SLOT_ID) -> Self {
		Slot {
			context,
			id,
		}
	}
}

impl Slot {
	/// Get the info of the token in this slot.
	pub fn token_info(&self) -> Result<pkcs11_sys::CK_TOKEN_INFO, GetTokenInfoError> {
		unsafe {
			let mut info = std::mem::MaybeUninit::uninit();

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

/// An error from getting a token's info.
#[derive(Debug)]
pub enum GetTokenInfoError {
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

impl Slot {
	pub fn open_session(&self, read_write: bool, pin: Option<String>) -> Result<std::sync::Arc<crate::Session>, OpenSessionError> {
		unsafe {
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
			let session = std::sync::Arc::new(crate::Session::new(self.context.clone(), handle, pin));

			Ok(session)
		}
	}
}

/// An error from opening a session against a slot.
#[derive(Debug)]
pub enum OpenSessionError {
	OpenSessionFailed(std::borrow::Cow<'static, str>),
}

impl std::fmt::Display for OpenSessionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			OpenSessionError::OpenSessionFailed(message) => write!(f, "could not open session: {}", message),
		}
	}
}

impl std::error::Error for OpenSessionError {
}

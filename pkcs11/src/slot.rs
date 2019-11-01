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
	/// Initialize the slot with the given label, SO PIN and user PIN.
	///
	/// If the slot was already initialized, it will be reinitialized. In this case the SO PIN must match what was originally set on the slot.
	pub fn initialize(&self, label: std::borrow::Cow<'_, str>, so_pin: &str, user_pin: &str) -> Result<(), InitializeSlotError> {
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
					Some(so_pin),
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
pub enum InitializeSlotError {
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

impl Slot {
	pub fn open_session(&self, read_write: bool, pin: Option<&str>) -> Result<std::sync::Arc<crate::Session>, OpenSessionError> {
		unsafe {
			self.open_session_inner(
				read_write,
				pkcs11_sys::CKU_USER,
				pin,
			)
		}
	}

	unsafe fn open_session_inner(
		&self,
		read_write: bool,
		user_type: pkcs11_sys::CK_USER_TYPE,
		pin: Option<&str>,
	) -> Result<std::sync::Arc<crate::Session>, OpenSessionError> {
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
		let session = std::sync::Arc::new(crate::Session::new(self.context.clone(), handle));

		if let Some(pin) = pin {
			let result =
				(self.context.C_Login)(
					session.handle,
					user_type,
					pin.as_ptr() as _,
					pin.len() as _,
				);
			if result != pkcs11_sys::CKR_OK && result != pkcs11_sys::CKR_USER_ALREADY_LOGGED_IN {
				return Err(OpenSessionError::LoginFailed(result));
			}
		}

		Ok(session)
	}
}

/// An error from opening a session against a slot.
#[derive(Debug)]
pub enum OpenSessionError {
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

/// Pad the given string to 32 bytes. Fails if the string is longer than 32 bytes.
#[allow(clippy::needless_lifetimes)]
fn pad_32<'a>(s: std::borrow::Cow<'a, str>) -> Result<std::borrow::Cow<'a, str>, ()> {
	match s.len() {
		len if len == 32 => Ok(s),
		len if len < 32 => Ok(format!("{:length$}", s, length = 32 - s.len() + s.chars().count()).into()),
		_ => Err(()),
	}
}

#[cfg(test)]
mod tests {
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

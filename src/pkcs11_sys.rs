#![allow(
	non_camel_case_types,
	non_snake_case,
)]


//! Refs:
//!
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html>
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html>


// Note: Section 2.1 "Structure packing" of the base spec says that all structs must be packed to 1 byte.
// In reality, this is only true of PKCS#11 libraries on Windows (which we don't support).
// For Linux, every PKCS#11 library tends to use no packing. Even if one of them didn't, libp11 itself expects
// the structs to not be packed.
//
// See https://github.com/opendnssec/SoftHSMv2/issues/471 for some relevant discussion (not specific to softhsm).


// CK_ATTRIBUTE

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_ATTRIBUTE {
	pub(crate) r#type: CK_ATTRIBUTE_TYPE,
	pub(crate) pValue: CK_VOID_PTR,
	pub(crate) ulValueLen: CK_ULONG,
}

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_ATTRIBUTE_IN {
	pub(crate) r#type: CK_ATTRIBUTE_TYPE,
	pub(crate) pValue: CK_VOID_PTR_CONST,
	pub(crate) ulValueLen: CK_ULONG,
}

pub(crate) type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;
pub(crate) type CK_ATTRIBUTE_PTR_CONST = *const CK_ATTRIBUTE;


// CK_ATTRIBUTE_TYPE

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_ATTRIBUTE_TYPE(CK_ULONG);

pub(crate) const CKA_DECRYPT: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0105);
pub(crate) const CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0180);
pub(crate) const CKA_EC_POINT: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0181);
pub(crate) const CKA_ENCRYPT: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0104);
pub(crate) const CKA_MODULUS: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0120);
pub(crate) const CKA_MODULUS_BITS: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0121);
pub(crate) const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0002);
pub(crate) const CKA_PUBLIC_EXPONENT: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0122);
pub(crate) const CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0103);
pub(crate) const CKA_SIGN: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0108);
pub(crate) const CKA_TOKEN: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0001);
pub(crate) const CKA_UNWRAP: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0107);
pub(crate) const CKA_VERIFY: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_010a);
pub(crate) const CKA_WRAP: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_0106);


// CK_BOOL

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_BOOL(u8);

pub(crate) const CK_TRUE: CK_BOOL = CK_BOOL(1);


// CK_BYTE

pub(crate) type CK_BYTE = u8;


// CK_FLAGS

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_FLAGS(CK_ULONG);

impl std::ops::BitOr<Self> for CK_FLAGS {
	type Output = Self;

	fn bitor(self, rhs: Self) -> Self::Output {
		CK_FLAGS(self.0 | rhs.0)
	}
}

impl std::ops::BitOrAssign for CK_FLAGS {
	fn bitor_assign(&mut self, rhs: Self) {
		self.0 |= rhs.0;
	}
}

pub(crate) const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = CK_FLAGS(0x0000_0001);
pub(crate) const CKF_RW_SESSION: CK_FLAGS = CK_FLAGS(0x0000_0002);
pub(crate) const CKF_SERIAL_SESSION: CK_FLAGS = CK_FLAGS(0x0000_0004);


// CK_FUNCTION_LIST

#[repr(C)]
pub(crate) struct CK_FUNCTION_LIST {
	pub(crate) version: CK_VERSION,

	pub(crate) C_Initialize: Option<CK_C_Initialize>,
	pub(crate) C_Finalize: Option<CK_C_Finalize>,
	pub(crate) C_GetInfo: Option<CK_C_GetInfo>,

	_unused1: [Option<unsafe extern "C" fn()>; 6],

	pub(crate) C_InitToken: Option<CK_C_InitToken>,
	pub(crate) C_InitPIN: Option<CK_C_InitPIN>,

	_unused2: Option<unsafe extern "C" fn()>,

	pub(crate) C_OpenSession: Option<CK_C_OpenSession>,
	pub(crate) C_CloseSession: Option<CK_C_CloseSession>,

	_unused3: [Option<unsafe extern "C" fn()>; 4],

	pub(crate) C_Login: Option<CK_C_Login>,
	pub(crate) C_Logout: Option<CK_C_Logout>,

	_unused4: [Option<unsafe extern "C" fn()>; 4],

	pub(crate) C_GetAttributeValue: Option<CK_C_GetAttributeValue>,

	_unused5: [Option<unsafe extern "C" fn()>; 34],

	pub(crate) C_GenerateKeyPair: Option<CK_C_GenerateKeyPair>,

	_unused6: [Option<unsafe extern "C" fn()>; 9],
}

pub(crate) type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub(crate) type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;


// CK_INFO

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_INFO {
	cryptokiVersion: CK_VERSION,
	manufacturerID: [CK_UTF8CHAR; 32],
	flags: CK_FLAGS,
	libraryDescription: [CK_UTF8CHAR; 32],
	libraryVersion: CK_VERSION,
}

pub(crate) type CK_INFO_PTR = *mut CK_INFO;

impl std::fmt::Display for CK_INFO {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"description: [{}], version: [{}], manufacturer ID: [{}], PKCS#11 version: [{}], flags: [{}]",
			String::from_utf8_lossy(&self.libraryDescription).trim(),
			self.libraryVersion,
			String::from_utf8_lossy(&self.manufacturerID).trim(),
			self.cryptokiVersion,
			self.flags.0,
		)?;
		Ok(())
	}
}


// CK_C_INITIALIZE_ARGS

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_C_INITIALIZE_ARGS {
	pub(crate) CreateMutex: CK_CREATEMUTEX,
	pub(crate) DestroyMutex: CK_DESTROYMUTEX,
	pub(crate) LockMutex: CK_LOCKMUTEX,
	pub(crate) UnlockMutex: CK_UNLOCKMUTEX,
	pub(crate) flags: CK_FLAGS,
	pub(crate) pReserved: CK_VOID_PTR,
}

pub(crate) type CK_C_INITIALIZE_ARGS_PTR = *const CK_C_INITIALIZE_ARGS;


// CK_MECHANISM

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_MECHANISM_IN {
	pub(crate) mechanism: CK_MECHANISM_TYPE,
	pub(crate) pParameter: CK_VOID_PTR_CONST,
	pub(crate) ulParameterLen: CK_ULONG,
}

pub(crate) type CK_MECHANISM_PTR_CONST = *const CK_MECHANISM_IN;


// CK_MECHANISM_TYPE

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_MECHANISM_TYPE(CK_ULONG);

pub(crate) const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = CK_MECHANISM_TYPE(0x0000_1040);
pub(crate) const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = CK_MECHANISM_TYPE(0x0000_0000);


// CK_NOTIFICATION

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_NOTIFICATION(CK_ULONG);


// CK_OBJECT_HANDLE

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct CK_OBJECT_HANDLE(CK_ULONG);

pub(crate) const CK_INVALID_OBJECT_HANDLE: CK_OBJECT_HANDLE = CK_OBJECT_HANDLE(0x0000_0000);

pub(crate) type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;


// CK_RV

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct CK_RV(CK_ULONG);

pub(crate) const CKR_ARGUMENTS_BAD: CK_RV = CK_RV(0x0000_0007);
pub(crate) const CKR_GENERAL_ERROR: CK_RV = CK_RV(0x0000_0005);
pub(crate) const CKR_OK: CK_RV = CK_RV(0x0000_0000);
pub(crate) const CKR_PIN_LEN_RANGE: CK_RV = CK_RV(0x0000_00a2);
pub(crate) const CKR_TEMPLATE_INCOMPLETE: CK_RV = CK_RV(0x0000_00d0);

impl std::fmt::Display for CK_RV {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match *self {
			CKR_ARGUMENTS_BAD => f.write_str("CKR_ARGUMENTS_BAD"),
			CKR_GENERAL_ERROR => f.write_str("CKR_GENERAL_ERROR"),
			CKR_OK => f.write_str("CKR_OK"),
			CKR_PIN_LEN_RANGE => f.write_str("CKR_PIN_LEN_RANGE"),
			CKR_TEMPLATE_INCOMPLETE => f.write_str("CKR_TEMPLATE_INCOMPLETE"),
			CK_RV(other) => write!(f, "0x{:08x}", other),
		}
	}
}


// CK_SESSION_HANDLE

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct CK_SESSION_HANDLE(CK_ULONG);

pub(crate) const CK_INVALID_SESSION_HANDLE: CK_SESSION_HANDLE = CK_SESSION_HANDLE(0x0000_0000);

pub(crate) type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;


// CK_SLOT_ID

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_SLOT_ID(CK_ULONG);

impl std::str::FromStr for CK_SLOT_ID {
	type Err = <CK_ULONG as std::str::FromStr>::Err;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(CK_SLOT_ID(std::str::FromStr::from_str(s)?))
	}
}


// CK_ULONG

pub(crate) type CK_ULONG = std::os::raw::c_ulong;


// CK_USER_TYPE

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_USER_TYPE(CK_ULONG);

pub(crate) const CKU_SO: CK_USER_TYPE = CK_USER_TYPE(0x0000_0000);
pub(crate) const CKU_USER: CK_USER_TYPE = CK_USER_TYPE(0x0000_0001);


// CK_UTF8CHAR

pub(crate) type CK_UTF8CHAR = CK_BYTE;

pub(crate) type CK_UTF8CHAR_PTR = *const CK_BYTE;


// CK_VERSION

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct CK_VERSION {
	pub(crate) major: CK_BYTE,
	pub(crate) minor: CK_BYTE,
}

impl std::fmt::Display for CK_VERSION {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "v{}.{}", self.major, self.minor)
	}
}


// CK_VOID

pub(crate) type CK_VOID = std::ffi::c_void;
pub(crate) type CK_VOID_PTR = *mut CK_VOID;
pub(crate) type CK_VOID_PTR_CONST = *const CK_VOID;
pub(crate) type CK_VOID_PTR_PTR = *mut CK_VOID_PTR;


// Function typedefs

pub(crate) type CK_C_CloseSession = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
) -> CK_RV;
pub(crate) type CK_C_Finalize = unsafe extern "C" fn(
	pReserved: CK_VOID_PTR,
) -> CK_RV;
pub(crate) type CK_C_GenerateKeyPair = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
	pMechanism: CK_MECHANISM_PTR_CONST,
	pPublicKeyTemplate: CK_ATTRIBUTE_PTR_CONST,
	ulPublicKeyAttributeCount: CK_ULONG,
	pPrivateKeyTemplate: CK_ATTRIBUTE_PTR_CONST,
	ulPrivateKeyAttributeCount: CK_ULONG,
	phPublicKey: CK_OBJECT_HANDLE_PTR,
	phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub(crate) type CK_C_GetAttributeValue = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
	hObject: CK_OBJECT_HANDLE,
	pTemplate: CK_ATTRIBUTE_PTR,
	ulCount: CK_ULONG,
) -> CK_RV;
pub(crate) type CK_C_GetFunctionList = unsafe extern "C" fn(
	ppFunctionList: CK_FUNCTION_LIST_PTR_PTR,
) -> CK_RV;
pub(crate) type CK_C_GetInfo = unsafe extern "C" fn(
	pInfo: CK_INFO_PTR,
) -> CK_RV;
pub(crate) type CK_C_Initialize = unsafe extern "C" fn(
	pReserved: CK_C_INITIALIZE_ARGS_PTR,
) -> CK_RV;
pub(crate) type CK_C_InitPIN = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
	pPin: CK_UTF8CHAR_PTR,
	ulPinLen: CK_ULONG,
) -> CK_RV;
pub(crate) type CK_C_InitToken = unsafe extern "C" fn(
	slotID: CK_SLOT_ID,
	pPin: CK_UTF8CHAR_PTR,
	ulPinLen: CK_ULONG,
	pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV;
pub(crate) type CK_C_Login = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
	userType: CK_USER_TYPE,
	pPin: CK_UTF8CHAR_PTR,
	ulPinLen: CK_ULONG,
) -> CK_RV;
pub(crate) type CK_C_Logout = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
) -> CK_RV;
pub(crate) type CK_C_OpenSession = unsafe extern "C" fn(
	slotID: CK_SLOT_ID,
	flags: CK_FLAGS,
	pApplication: CK_VOID_PTR,
	Notify: Option<CK_NOTIFY>,
	phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV;

pub(crate) type CK_CREATEMUTEX = unsafe extern "C" fn(ppMutex: CK_VOID_PTR_PTR) -> CK_RV;
pub(crate) type CK_DESTROYMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;
pub(crate) type CK_LOCKMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;
pub(crate) type CK_UNLOCKMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;

pub(crate) type CK_NOTIFY = unsafe extern "C" fn(
	hSession: CK_SESSION_HANDLE,
	event: CK_NOTIFICATION,
	pApplication: CK_VOID_PTR,
) -> CK_RV;

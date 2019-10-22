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
pub(crate) const CKA_VERIFY: CK_ATTRIBUTE_TYPE = CK_ATTRIBUTE_TYPE(0x0000_010a);


// CK_BBOOL

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_BBOOL(u8);

pub(crate) const CK_TRUE: CK_BBOOL = CK_BBOOL(1);


// CK_BYTE

pub(crate) type CK_BYTE = u8;


// CK_CHAR

pub(crate) type CK_CHAR = CK_BYTE;


// CK_FLAGS

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_INITIALIZE_FLAGS(CK_ULONG);

pub(crate) const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_INITIALIZE_FLAGS = CK_INITIALIZE_FLAGS(0x0000_0001);

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_OPEN_SESSION_FLAGS(CK_ULONG);

impl std::ops::BitOr<Self> for CK_OPEN_SESSION_FLAGS {
	type Output = Self;

	fn bitor(self, rhs: Self) -> Self::Output {
		CK_OPEN_SESSION_FLAGS(self.0 | rhs.0)
	}
}

impl std::ops::BitOrAssign for CK_OPEN_SESSION_FLAGS {
	fn bitor_assign(&mut self, rhs: Self) {
		self.0 |= rhs.0;
	}
}

pub(crate) const CKF_RW_SESSION: CK_OPEN_SESSION_FLAGS = CK_OPEN_SESSION_FLAGS(0x0000_0002);
pub(crate) const CKF_SERIAL_SESSION: CK_OPEN_SESSION_FLAGS = CK_OPEN_SESSION_FLAGS(0x0000_0004);

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct CK_TOKEN_INFO_FLAGS(CK_ULONG);

impl CK_TOKEN_INFO_FLAGS {
	pub(crate) fn has(self, other: Self) -> bool {
		(self.0 & other.0) != 0
	}
}

pub(crate) const CKF_TOKEN_INITIALIZED: CK_TOKEN_INFO_FLAGS = CK_TOKEN_INFO_FLAGS(0x0000_0400);


// CK_FUNCTION_LIST

#[repr(C)]
pub(crate) struct CK_FUNCTION_LIST {
	pub(crate) version: CK_VERSION,

	pub(crate) C_Initialize: Option<CK_C_Initialize>,
	pub(crate) C_Finalize: Option<CK_C_Finalize>,
	pub(crate) C_GetInfo: Option<CK_C_GetInfo>,

	_unused1: [Option<unsafe extern "C" fn()>; 1],

	pub(crate) C_GetSlotList: Option<CK_C_GetSlotList>,

	_unused2: [Option<unsafe extern "C" fn()>; 1],

	pub(crate) C_GetTokenInfo: Option<CK_C_GetTokenInfo>,

	_unused3: [Option<unsafe extern "C" fn()>; 2],

	pub(crate) C_InitToken: Option<CK_C_InitToken>,
	pub(crate) C_InitPIN: Option<CK_C_InitPIN>,

	_unused4: [Option<unsafe extern "C" fn()>; 1],

	pub(crate) C_OpenSession: Option<CK_C_OpenSession>,
	pub(crate) C_CloseSession: Option<CK_C_CloseSession>,

	_unused5: [Option<unsafe extern "C" fn()>; 4],

	pub(crate) C_Login: Option<CK_C_Login>,
	pub(crate) C_Logout: Option<CK_C_Logout>,

	_unused6: [Option<unsafe extern "C" fn()>; 4],

	pub(crate) C_GetAttributeValue: Option<CK_C_GetAttributeValue>,

	_unused7: [Option<unsafe extern "C" fn()>; 34],

	pub(crate) C_GenerateKeyPair: Option<CK_C_GenerateKeyPair>,

	_unused8: [Option<unsafe extern "C" fn()>; 8],
}

pub(crate) type CK_FUNCTION_LIST_PTR_CONST = *const CK_FUNCTION_LIST;
pub(crate) type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR_CONST;


// CK_INFO

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_INFO {
	pub(crate) cryptokiVersion: CK_VERSION,
	pub(crate) manufacturerID: [CK_UTF8CHAR; 32],
	pub(crate) flags: CK_ULONG,
	pub(crate) libraryDescription: [CK_UTF8CHAR; 32],
	pub(crate) libraryVersion: CK_VERSION,
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
			self.flags,
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
	pub(crate) flags: CK_INITIALIZE_FLAGS,
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

macro_rules! define_CK_RV {
	(@inner $f:ident ( $($consts:tt)* ) ( $($match_arms:tt)* ) ()) => {
		$($consts)*

		impl std::fmt::Display for CK_RV {
			fn fmt(&self, $f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				match *self {
					$($match_arms)*
					CK_RV(other) => write!($f, "0x{:08x}", other),
				}
			}
		}
	};

	(@inner $f:ident ( $($consts:tt)* ) ( $($match_arms:tt)* ) ( $ident:ident = $value:expr, $($rest:tt)* )) => {
		define_CK_RV! {
			@inner
			$f
			( $($consts)* pub(crate) const $ident: CK_RV = CK_RV($value); )
			( $($match_arms)* $ident => $f.write_str(stringify!($ident)), )
			( $($rest)* )
		}
	};

	($($tt:tt)*) => {
		define_CK_RV! {
			@inner
			f
			( )
			( )
			( $($tt)* )
		}
	};
}

define_CK_RV! {
	CKR_ARGUMENTS_BAD = 0x0000_0007,
	CKR_ATTRIBUTE_TYPE_INVALID = 0x0000_0012,

	CKR_BUFFER_TOO_SMALL = 0x0000_0150,

	CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x0000_0191,
	CKR_CRYPTOKI_NOT_INITIALIZED = 0x0000_0190,
	CKR_CURVE_NOT_SUPPORTED = 0x0000_0140,

	CKR_DEVICE_ERROR = 0x0000_0030,
	CKR_DEVICE_MEMORY = 0x0000_0031,
	CKR_DEVICE_REMOVED = 0x0000_0032,

	CKR_FUNCTION_FAILED = 0x0000_0006,
	CKR_FUNCTION_NOT_SUPPORTED = 0x0000_0054,

	CKR_GENERAL_ERROR = 0x0000_0005,

	CKR_HOST_MEMORY = 0x0000_0002,

	CKR_KEY_FUNCTION_NOT_PERMITTED = 0x0000_0068,
	CKR_KEY_HANDLE_INVALID = 0x000_0060,
	CKR_KEY_SIZE_RANGE = 0x0000_0062,
	CKR_KEY_TYPE_INCONSISTENT = 0x0000_0063,

	CKR_LIBRARY_LOAD_FAILED = 0x0000_01c2,

	CKR_MECHANISM_INVALID = 0x0000_0070,
	CKR_MUTEX_BAD = 0x0000_01a0,
	CKR_MUTEX_NOT_LOCKED = 0x0000_01a1,

	CKR_NEED_TO_CREATE_THREADS = 0x0000_0009,

	CKR_OBJECT_HANDLE_INVALID = 0x0000_0082,
	CKR_OK = 0x0000_0000,
	CKR_OPERATION_ACTIVE = 0x0000_0090,

	CKR_PIN_EXPIRED = 0x0000_00a3,
	CKR_PIN_LEN_RANGE = 0x0000_00a2,
	CKR_PIN_LOCKED = 0x0000_00a4,
	CKR_PIN_TOO_WEAK = 0x0000_01c3,

	CKR_SESSION_CLOSED = 0x0000_00b0,
	CKR_SESSION_COUNT = 0x0000_00b1,
	CKR_SESSION_EXISTS = 0x0000_00b6,
	CKR_SESSION_HANDLE_INVALID = 0x0000_00b3,
	CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x0000_00b4,
	CKR_SESSION_READ_ONLY = 0x0000_00b5,
	CKR_SESSION_READ_ONLY_EXISTS = 0x0000_00b7,
	CKR_SESSION_READ_WRITE_EXISTS = 0x0000_00b8,
	CKR_SLOT_ID_INVALID = 0x0000_0003,

	CKR_TEMPLATE_INCOMPLETE = 0x0000_00d0,
	CKR_TOKEN_NOT_PRESENT = 0x0000_00e0,
}


// CK_SESSION_HANDLE

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct CK_SESSION_HANDLE(CK_ULONG);

pub(crate) const CK_INVALID_SESSION_HANDLE: CK_SESSION_HANDLE = CK_SESSION_HANDLE(0x0000_0000);

pub(crate) type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;


// CK_SLOT_ID

#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub(crate) struct CK_SLOT_ID(pub CK_ULONG);

impl std::str::FromStr for CK_SLOT_ID {
	type Err = <CK_ULONG as std::str::FromStr>::Err;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(CK_SLOT_ID(std::str::FromStr::from_str(s)?))
	}
}

pub(crate) type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;


// CK_TOKEN_INFO

#[derive(Debug)]
#[repr(C)]
pub(crate) struct CK_TOKEN_INFO {
	pub(crate) label: [CK_UTF8CHAR; 32],
	pub(crate) manufacturerID: [CK_UTF8CHAR; 32],
	pub(crate) model: [CK_UTF8CHAR; 16],
	pub(crate) serialNumber: [CK_CHAR; 16],
	pub(crate) flags: CK_TOKEN_INFO_FLAGS,
	pub(crate) ulMaxSessionCount: CK_ULONG,
	pub(crate) ulSessionCount: CK_ULONG,
	pub(crate) ulMaxRwSessionCount: CK_ULONG,
	pub(crate) ulRwSessionCount: CK_ULONG,
	pub(crate) ulMaxPinLen: CK_ULONG,
	pub(crate) ulMinPinLen: CK_ULONG,
	pub(crate) ulTotalPublicMemory: CK_ULONG,
	pub(crate) ulFreePublicMemory: CK_ULONG,
	pub(crate) ulTotalPrivateMemory: CK_ULONG,
	pub(crate) ulFreePrivateMemory: CK_ULONG,
	pub(crate) hardwareVersion: CK_VERSION,
	pub(crate) firmwareVersion: CK_VERSION,
	pub(crate) utcTime: [CK_CHAR; 16],
}

pub(crate) type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;


// CK_ULONG

pub(crate) type CK_ULONG = std::os::raw::c_ulong;

pub(crate) type CK_ULONG_PTR = *mut CK_ULONG;


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
pub(crate) type CK_C_GetSlotList = unsafe extern "C" fn(
	tokenPresent: CK_BBOOL,
	pSlotList: CK_SLOT_ID_PTR,
	pulCount: CK_ULONG_PTR,
) -> CK_RV;
pub(crate) type CK_C_GetTokenInfo = unsafe extern "C" fn(
	slotID: CK_SLOT_ID,
	pInfo: CK_TOKEN_INFO_PTR,
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
	flags: CK_OPEN_SESSION_FLAGS,
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


#[cfg(test)]
mod tests {
	#[test]
	fn CK_FUNCTION_LIST() {
		// CK_FUNCTION_LIST has a CK_VERSION padded to sizeof uintptr_t + 68 function pointers
		assert_eq!(
			std::mem::size_of::<super::CK_FUNCTION_LIST>(),
			std::mem::size_of::<usize>() + 68 * std::mem::size_of::<usize>(),
		);
	}
}

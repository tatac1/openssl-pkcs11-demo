#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::not_unsafe_ptr_arg_deref,
	clippy::use_self,
)]

use openssl_sys2;

/// Error type for openssl engine operations.
#[derive(Debug)]
pub enum Error {
	SysReturnedNull { inner: openssl::error::ErrorStack, },
	SysReturnedUnexpected { expected: std::os::raw::c_int, actual: std::os::raw::c_int, inner: openssl::error::ErrorStack, },
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::SysReturnedNull { .. } => write!(f, "expected operation to return valid pointer but it returned NULL"),
			Error::SysReturnedUnexpected { expected, actual, .. } => write!(f, "expected operation to return {} but it returned {}", expected, actual),
		}
	}
}

impl std::error::Error for Error {
	#[allow(clippy::match_same_arms)]
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::SysReturnedNull { inner } => Some(inner),
			Error::SysReturnedUnexpected { inner, .. } => Some(inner),
		}
	}
}

/// A "structural reference" to an openssl engine.
pub struct StructuralEngine {
	inner: *mut openssl_sys::ENGINE,
}

impl StructuralEngine {
	/// Loads an engine by its ID.
	pub fn by_id(id: &std::ffi::CStr) -> Result<Self, Error> {
		unsafe {
			let inner = openssl_returns_nonnull(openssl_sys2::ENGINE_by_id(id.as_ptr()))?;
			Ok(StructuralEngine {
				inner,
			})
		}
	}

	/// Convert a raw `*mut ENGINE` to a `StructuralEngine`
	pub fn from_ptr(e: *mut openssl_sys::ENGINE) -> Self {
		StructuralEngine {
			inner: e,
		}
	}
}

impl Drop for StructuralEngine {
	fn drop(&mut self) {
		unsafe {
			let _ = openssl_sys2::ENGINE_free(self.inner);
		}
	}
}

/// A "functional reference" to an openssl engine.
///
/// Can be obtained by using [`std::convert::TryInto::try_into`] on a [`StructuralEngine`]
pub struct FunctionalEngine {
	inner: *mut openssl_sys::ENGINE,
}

impl FunctionalEngine {
	/// Queries the engine for its name.
	pub fn name(&self) -> Result<&std::ffi::CStr, Error> {
		unsafe {
			let name = openssl_returns_nonnull_const(openssl_sys2::ENGINE_get_name(self.inner))?;
			let name = std::ffi::CStr::from_ptr(name);
			Ok(name)
		}
	}

	/// Returns the raw `*mut ENGINE` contained in this instance.
	pub fn as_ptr(&self) -> *mut openssl_sys::ENGINE {
		self.inner
	}

	/// Loads the public key with the given ID.
	pub fn load_public_key(&mut self, id: &std::ffi::CStr) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
		unsafe {
			let result =
				openssl_returns_nonnull(openssl_sys2::ENGINE_load_public_key(
					self.inner,
					id.as_ptr(),
					std::ptr::null_mut(),
					std::ptr::null_mut(),
				))?;
			let result = foreign_types_shared::ForeignType::from_ptr(result);
			Ok(result)
		}
	}

	/// Loads the private key with the given ID.
	pub fn load_private_key(&mut self, id: &std::ffi::CStr) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Error> {
		unsafe {
			let result =
				openssl_returns_nonnull(openssl_sys2::ENGINE_load_private_key(
					self.inner,
					id.as_ptr(),
					std::ptr::null_mut(),
					std::ptr::null_mut(),
				))?;
			let result = foreign_types_shared::ForeignType::from_ptr(result);
			Ok(result)
		}
	}
}

impl Drop for FunctionalEngine {
	fn drop(&mut self) {
		unsafe {
			let _ = openssl_sys2::ENGINE_finish(self.inner);
		}
	}
}

impl std::convert::TryFrom<StructuralEngine> for FunctionalEngine {
	type Error = Error;

	fn try_from(engine: StructuralEngine) -> Result<Self, Self::Error> {
		unsafe {
			let inner = engine.inner;

			openssl_returns_1(openssl_sys2::ENGINE_init(inner))?;

			// ENGINE_finish releases the original structural reference as well, so we don't want to call ENGINE_free on the original StructuralEngine now.
			std::mem::forget(engine);

			Ok(FunctionalEngine {
				inner,
			})
		}
	}
}

pub fn openssl_returns_1(result: std::os::raw::c_int) -> Result<(), Error> {
	if result == 1 {
		Ok(())
	}
	else {
		Err(Error::SysReturnedUnexpected { expected: 1, actual: result, inner: openssl::error::ErrorStack::get() })
	}
}

pub fn openssl_returns_nonnull<T>(result: *mut T) -> Result<*mut T, Error> {
	if result.is_null() {
		Err(Error::SysReturnedNull { inner: openssl::error::ErrorStack::get() })
	}
	else {
		Ok(result)
	}
}

pub fn openssl_returns_nonnull_const<T>(result: *const T) -> Result<*const T, Error> {
	if result.is_null() {
		Err(Error::SysReturnedNull { inner: openssl::error::ErrorStack::get() })
	}
	else {
		Ok(result)
	}
}

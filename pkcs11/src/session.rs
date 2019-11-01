pub struct Session {
	pub(crate) context: std::sync::Arc<crate::Context>,
	pub(crate) handle: pkcs11_sys::CK_SESSION_HANDLE,
}

impl Session {
	pub(crate) fn new(
		context: std::sync::Arc<crate::Context>,
		handle: pkcs11_sys::CK_SESSION_HANDLE,
	) -> Self {
		Session {
			context,
			handle,
		}
	}
}

pub enum KeyPair {
	Ec(
		crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>,
		crate::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
	),
	Rsa(
		crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>,
		crate::Object<openssl::rsa::Rsa<openssl::pkey::Private>>,
	),
}

pub enum PublicKey {
	Ec(crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>),
	Rsa(crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>),
}

impl Session {
	pub fn get_public_key(self: std::sync::Arc<Self>) -> Result<PublicKey, FindObjectError> {
		unsafe {
			let (public_key_handle, public_key_mechanism_type) = self.get_key_inner(pkcs11_sys::CKO_PUBLIC_KEY)?;

			match public_key_mechanism_type {
				pkcs11_sys::CKK_EC => Ok(PublicKey::Ec(crate::Object::new(self.clone(), public_key_handle))),
				pkcs11_sys::CKK_RSA => Ok(PublicKey::Rsa(crate::Object::new(self, public_key_handle))),
				_ => Err(FindObjectError::MismatchedMechanismType),
			}
		}
	}

	pub fn get_key_pair(self: std::sync::Arc<Self>) -> Result<KeyPair, FindObjectError> {
		unsafe {
			let (public_key_handle, public_key_mechanism_type) = self.get_key_inner(pkcs11_sys::CKO_PUBLIC_KEY)?;
			let (private_key_handle, private_key_mechanism_type) = self.get_key_inner(pkcs11_sys::CKO_PRIVATE_KEY)?;

			match (public_key_mechanism_type, private_key_mechanism_type) {
				(pkcs11_sys::CKK_EC, pkcs11_sys::CKK_EC) => Ok(KeyPair::Ec(
					crate::Object::new(self.clone(), public_key_handle),
					crate::Object::new(self, private_key_handle),
				)),

				(pkcs11_sys::CKK_RSA, pkcs11_sys::CKK_RSA) => Ok(KeyPair::Rsa(
					crate::Object::new(self.clone(), public_key_handle),
					crate::Object::new(self, private_key_handle),
				)),

				_ => Err(FindObjectError::MismatchedMechanismType),
			}
		}
	}

	unsafe fn get_key_inner(
		&self,
		class: pkcs11_sys::CK_OBJECT_CLASS,
	) -> Result<(pkcs11_sys::CK_OBJECT_HANDLE, pkcs11_sys::CK_KEY_TYPE), FindObjectError> {
		let template = pkcs11_sys::CK_ATTRIBUTE_IN {
			r#type: pkcs11_sys::CKA_CLASS,
			pValue: &class as *const _ as _,
			ulValueLen: std::mem::size_of_val(&class) as _,
		};

		let _find_object = FindObject::new(self, &template)?;

		let mut key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
		let mut num_objects = 0;
		let result =
			(self.context.C_FindObjects)(
				self.handle,
				&mut key_handle,
				1,
				&mut num_objects,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(FindObjectError::FindObjectsFailed(format!("C_FindObjects failed with {}", result).into()));
		}
		if num_objects != 1 {
			return Err(FindObjectError::FindObjectsFailed(format!("C_FindObjects found {} keys", num_objects).into()));
		}
		if key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
			return Err(FindObjectError::FindObjectsFailed("C_FindObjects found 1 key but key handle is still CK_INVALID_HANDLE".into()));
		}

		let mut key_type = pkcs11_sys::CKK_EC;
		let key_type_size = std::mem::size_of_val(&key_type) as _;
		let mut attribute = pkcs11_sys::CK_ATTRIBUTE {
			r#type: pkcs11_sys::CKA_KEY_TYPE,
			pValue: &mut key_type as *mut _ as _,
			ulValueLen: key_type_size,
		};
		let result =
			(self.context.C_GetAttributeValue)(
				self.handle,
				key_handle,
				&mut attribute,
				1,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(FindObjectError::GetKeyTypeFailed(result));
		}

		Ok((key_handle, key_type))
	}
}

struct FindObject<'session> {
	session: &'session Session,
}

impl<'session> FindObject<'session> {
	unsafe fn new(
		session: &'session Session,
		template: &pkcs11_sys::CK_ATTRIBUTE_IN,
	) -> Result<Self, FindObjectError> {
		let result =
			(session.context.C_FindObjectsInit)(
				session.handle,
				template,
				1,
			);
		if result != pkcs11_sys::CKR_OK {
			return Err(FindObjectError::FindObjectsInitFailed(result));
		}

		Ok(FindObject {
			session,
		})
	}
}

impl<'session> Drop for FindObject<'session> {
	fn drop(&mut self) {
		unsafe {
			let _ = (self.session.context.C_FindObjectsFinal)(self.session.handle);
		}
	}
}

/// An error from finding an object.
#[derive(Debug)]
pub enum FindObjectError {
	FindObjectsFailed(std::borrow::Cow<'static, str>),
	FindObjectsInitFailed(pkcs11_sys::CK_RV),
	GetKeyTypeFailed(pkcs11_sys::CK_RV),
	MismatchedMechanismType,
}

impl std::fmt::Display for FindObjectError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			FindObjectError::FindObjectsFailed(message) => f.write_str(message),
			FindObjectError::FindObjectsInitFailed(result) => write!(f, "C_FindObjectsInit failed with {}", result),
			FindObjectError::GetKeyTypeFailed(result) => write!(f, "C_GetAttributeValue(CKA_KEY_TYPE) failed with {}", result),
			FindObjectError::MismatchedMechanismType => f.write_str("public and private keys have different mechanisms"),
		}
	}
}

impl std::error::Error for FindObjectError {
}

impl Session {
	pub fn generate_ec_key_pair(
		self: std::sync::Arc<Self>,
		curve: crate::EcCurve,
	) -> Result<(crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>, crate::Object<openssl::ec::EcKey<openssl::pkey::Private>>), GenerateKeyPairError> {
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

	pub fn generate_rsa_key_pair(
		self: std::sync::Arc<Self>,
		modulus_bits: pkcs11_sys::CK_ULONG,
		exponent: &openssl::bn::BigNum,
	) -> Result<(crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>, crate::Object<openssl::rsa::Rsa<openssl::pkey::Private>>), GenerateKeyPairError> {
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
		self: std::sync::Arc<Self>,
		mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
		mut public_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
		mut private_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
	) -> Result<(crate::Object<TPublic>, crate::Object<TPrivate>), GenerateKeyPairError> {
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
			(self.context.C_GenerateKeyPair)(
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
			crate::Object::new(self.clone(), public_key_handle),
			crate::Object::new(self, private_key_handle),
		))
	}
}

/// An error from generating a key pair.
#[derive(Debug)]
pub enum GenerateKeyPairError {
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

impl Drop for Session {
	fn drop(&mut self) {
		unsafe {
			let _ = (self.context.C_CloseSession)(self.handle);
		}
	}
}

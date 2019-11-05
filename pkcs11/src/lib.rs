#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	non_snake_case,
	clippy::default_trait_access,
	clippy::type_complexity,
	clippy::use_self,
)]

mod context;
pub use context::{
	Context,
	LoadContextError, ListSlotsError,
};

mod dl;

mod object;
pub use object::{
	Object,
	EncryptError, GetKeyParametersError, SignError,
};

mod session;
pub use session::{
	KeyPair, PublicKey, Session,
	FindObjectError, GenerateKeyPairError, LoginError,
};

mod slot;
pub use slot::{
	Slot,
	GetTokenInfoError, OpenSessionError,
};

/// The kinds of EC curves supported for key generation.
#[cfg_attr(not(ossl110), allow(clippy::pub_enum_variant_names))] // "All variants start with Nist"
#[derive(Clone, Copy, Debug)]
pub enum EcCurve {
	/// ed25519
	///
	/// Note: Requires openssl >= 1.1.1
	///
	/// Note: This has not been tested since softhsm does not support it, which in turn is because openssl (as of v1.1.1c) does not support it
	/// for key generation.
	#[cfg(ossl110)]
	Ed25519,

	/// secp256r1, known to openssl as prime256v1
	NistP256,

	/// secp384r1
	NistP384,

	/// secp521r1
	NistP521,
}

impl EcCurve {
	#[cfg(ossl110)]
	const ED25519_OID_DER: &'static [u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
	const SECP256R1_OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
	const SECP384R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
	const SECP521R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

	fn as_nid(self) -> openssl::nid::Nid {
		match self {
			#[cfg(ossl110)]
			EcCurve::Ed25519 => openssl::nid::Nid::from_raw(openssl_sys::NID_ED25519), // Not wrapped by openssl as of v0.10.25
			EcCurve::NistP256 => openssl::nid::Nid::X9_62_PRIME256V1,
			EcCurve::NistP384 => openssl::nid::Nid::SECP384R1,
			EcCurve::NistP521 => openssl::nid::Nid::SECP521R1,
		}
	}

	fn as_oid_der(self) -> &'static [u8] {
		match self {
			#[cfg(ossl110)]
			EcCurve::Ed25519 => EcCurve::ED25519_OID_DER,
			EcCurve::NistP256 => EcCurve::SECP256R1_OID_DER,
			EcCurve::NistP384 => EcCurve::SECP384R1_OID_DER,
			EcCurve::NistP521 => EcCurve::SECP521R1_OID_DER,
		}
	}

	fn from_oid_der(oid: &[u8]) -> Option<Self> {
		match oid {
			#[cfg(ossl110)]
			EcCurve::ED25519_OID_DER => Some(EcCurve::Ed25519),
			EcCurve::SECP256R1_OID_DER => Some(EcCurve::NistP256),
			EcCurve::SECP384R1_OID_DER => Some(EcCurve::NistP384),
			EcCurve::SECP521R1_OID_DER => Some(EcCurve::NistP521),
			_ => None,
		}
	}
}

#[derive(Debug, PartialEq)]
pub struct Uri {
	pub slot_identifier: UriSlotIdentifier,
	pub pin: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum UriSlotIdentifier {
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

		Ok(Uri {
			slot_identifier,
			pin,
		})
	}
}

#[derive(Debug)]
pub enum ParsePkcs11UriError {
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

#[cfg(test)]
mod tests {
	#[test]
	fn parse_pkcs11_uri() {
		assert_eq!(
			"pkcs11:slot-id=1?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::SlotId(pkcs11_sys::CK_SLOT_ID(1)),
				pin: Some("1234".to_owned()),
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: Some("1234".to_owned()),
			},
		);

		assert_eq!(
			"pkcs11:slot-id=1;token=Foo%20Bar?pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::SlotId(pkcs11_sys::CK_SLOT_ID(1)),
				pin: Some("1234".to_owned()),
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: None,
			},
		);

		assert_eq!(
			"pkcs11:token=Foo%20Bar;foo=bar?baz=quux&pin-value=1234".parse::<super::Uri>().unwrap(),
			super::Uri {
				slot_identifier: super::UriSlotIdentifier::Label("Foo Bar".to_owned()),
				pin: Some("1234".to_owned()),
			},
		);

		let _ = "kcs11:token=Foo%20Bar".parse::<super::Uri>().expect_err("expect URI with invalid scheme to fail to parse");

		let _ = "pkcs11:".parse::<super::Uri>().expect_err("expect URI with neither label nor slot ID to fail to parse");
	}
}

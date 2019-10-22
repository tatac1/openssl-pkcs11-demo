#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::option_map_unwrap_or_else, // Workaround until structopt_derive 0.3.3. See https://github.com/TeXitoi/structopt/pull/264
	clippy::type_complexity,
	clippy::use_self,
)]

mod dl;
mod openssl2;
mod openssl_sys2;
mod pkcs11;
mod pkcs11_sys;
mod tokio_openssl2;

fn main() -> Result<(), Error> {
	openssl::init();
	openssl2::init();

	let Options {
		command,
		pkcs11_engine_path,
		pkcs11_lib_path,
		use_pkcs11_spy,
		verbose,
	} = structopt::StructOpt::from_args();

	let pkcs11_lib_path =
		if let Some(use_pkcs11_spy) = use_pkcs11_spy {
			let pkcs11_spy_path = use_pkcs11_spy.unwrap_or_else(|| "/usr/lib64/pkcs11/pkcs11-spy.so".into());
			std::env::set_var("PKCS11SPY", &pkcs11_lib_path);
			pkcs11_spy_path
		}
		else {
			pkcs11_lib_path
		};

	match command {
		Command::GenerateCaCert { key, out_file, subject } => {
			let mut engine = load_engine(&pkcs11_engine_path, &pkcs11_lib_path, verbose)?;

			let mut builder = openssl::x509::X509::builder()?;

			let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
			builder.set_not_after(std::borrow::Borrow::borrow(&not_after))?;

			let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
			builder.set_not_before(std::borrow::Borrow::borrow(&not_before))?;

			let mut subject_name = openssl::x509::X509Name::builder()?;
			subject_name.append_entry_by_text("CN", &subject)?;
			let subject_name = subject_name.build();
			builder.set_subject_name(&subject_name)?;
			builder.set_issuer_name(&subject_name)?;

			let public_key = load_public_key(&mut engine, key.clone())?;
			builder.set_pubkey(&public_key)?;

			let ca_extension = openssl::x509::extension::BasicConstraints::new().ca().build()?;
			builder.append_extension(ca_extension)?;

			let private_key = load_private_key(&mut engine, key)?;
			builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;

			let cert = builder.build();

			let cert = cert.to_pem()?;

			std::fs::write(out_file, &cert)?;
		},

		Command::GenerateCert { ca_cert, ca_key, key, out_file, subject } => {
			let mut engine = load_engine(&pkcs11_engine_path, &pkcs11_lib_path, verbose)?;

			let mut builder = openssl::x509::X509::builder()?;

			let not_after = openssl::asn1::Asn1Time::days_from_now(30)?;
			builder.set_not_after(std::borrow::Borrow::borrow(&not_after))?;

			let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
			builder.set_not_before(std::borrow::Borrow::borrow(&not_before))?;

			let mut subject_name = openssl::x509::X509Name::builder()?;
			subject_name.append_entry_by_text("CN", &subject)?;
			let subject_name = subject_name.build();
			builder.set_subject_name(&subject_name)?;

			let ca_cert = std::fs::read(ca_cert)?;
			let ca_cert = openssl::x509::X509::from_pem(&ca_cert)?;
			builder.set_issuer_name(ca_cert.subject_name())?;

			let public_key = load_public_key(&mut engine, key.clone())?;
			builder.set_pubkey(&public_key)?;

			let server_extension = openssl::x509::extension::ExtendedKeyUsage::new().server_auth().build()?;
			builder.append_extension(server_extension)?;

			let ca_private_key = load_private_key(&mut engine, ca_key)?;
			builder.sign(&ca_private_key, openssl::hash::MessageDigest::sha256())?;

			let cert = builder.build();

			let cert = cert.to_pem()?;
			let ca_cert = ca_cert.to_pem()?;

			let mut out_file = std::fs::File::create(out_file)?;
			std::io::Write::write_all(&mut out_file, &cert)?;
			std::io::Write::write_all(&mut out_file, &ca_cert)?;
			std::io::Write::flush(&mut out_file)?;
		},

		Command::GenerateKeyPair { key, r#type } => {
			let key: pkcs11::Uri = key.parse()?;

			let pkcs11_context = pkcs11::Context::load(pkcs11_lib_path)?;
			if let Some(info) = pkcs11_context.info() {
				println!("Loaded PKCS#11 library: {}", info);
			}
			else {
				println!("Loaded PKCS#11 library: <unknown>");
			}

			let pkcs11_slot = match key.slot_identifier {
				pkcs11::UriSlotIdentifier::Label(label) => {
					let mut slot = None;
					for context_slot in pkcs11_context.slots()? {
						let token_info = context_slot.token_info()?;
						if !token_info.flags.has(pkcs11_sys::CKF_TOKEN_INITIALIZED) {
							continue;
						}

						let slot_label = String::from_utf8_lossy(&token_info.label).trim().to_owned();
						if slot_label != label {
							continue;
						}

						slot = Some(context_slot);
						break;
					}

					slot.ok_or("could not find slot with matching label")?
				},

				pkcs11::UriSlotIdentifier::SlotId(slot_id) => pkcs11_context.slot(slot_id),
			};

			let pkcs11_session = pkcs11_slot.open_session(true, &key.pin)?;

			match r#type {
				KeyType::Ec(curve) => {
					let (public_key_handle, _) = pkcs11_session.generate_ec_key_pair(curve)?;
					let public_key_parameters = public_key_handle.parameters()?;
					let public_key_parameters = Displayable(public_key_parameters);
					println!("Created EC key with parameters {}", public_key_parameters);
				},

				KeyType::Rsa(modulus_bits) => {
					let exponent = openssl_sys::RSA_F4;
					let exponent = exponent.to_be_bytes();
					let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

					let (public_key_handle, _) = pkcs11_session.generate_rsa_key_pair(modulus_bits, &exponent)?;
					let public_key_parameters = public_key_handle.parameters()?;
					let public_key_parameters = Displayable(public_key_parameters);
					println!("Created RSA key with parameters {}", public_key_parameters);
				},
			}
		},

		Command::InitializeSlot { label, slot_id, so_pin, user_pin } => {
			let pkcs11_context = pkcs11::Context::load(pkcs11_lib_path)?;
			if let Some(info) = pkcs11_context.info() {
				println!("Loaded PKCS#11 library: {}", info);
			}
			else {
				println!("Loaded PKCS#11 library: <unknown>");
			}

			let mut pkcs11_slot = pkcs11_context.slot(slot_id);

			pkcs11_slot.initialize(label.into(), &so_pin, &user_pin)?;
		},

		Command::Load { keys } => {
			let mut engine = load_engine(&pkcs11_engine_path, &pkcs11_lib_path, verbose)?;
			for key in keys {
				let key = load_public_key(&mut engine, key)?;

				if let Ok(ec_key) = key.ec_key() {
					let ec_key = Displayable(ec_key);
					println!("Loaded EC key with parameters {}", ec_key);
				}
				else if let Ok(rsa) = key.rsa() {
					let rsa = Displayable(rsa);
					println!("Loaded RSA key with parameters {}", rsa);
				}
			}
		},

		Command::WebServer { cert, key, port } => {
			let mut engine = load_engine(&pkcs11_engine_path, &pkcs11_lib_path, verbose)?;

			let key = load_private_key(&mut engine, key)?;

			let mut runtime = tokio::runtime::Runtime::new()?;

			let listener = std::net::TcpListener::bind(&("0.0.0.0", port))?;
			let incoming =
				tokio_openssl2::Incoming::new(
					listener,
					&cert,
					&key,
				)?;

			let server =
				hyper::Server::builder(incoming)
				.serve(|| hyper::service::service_fn_ok(|_| hyper::Response::new(hyper::Body::from("Hello, world!\n"))));

			runtime.block_on(server)?;
		},
	}

	Ok(())
}

fn load_engine(
	pkcs11_engine_path: &std::path::Path,
	pkcs11_lib_path: &std::path::Path,
	verbose: bool,
) -> Result<openssl2::FunctionalEngine, Error> {
	let mut pkcs11_engine_path = std::os::unix::ffi::OsStrExt::as_bytes(pkcs11_engine_path.as_os_str()).to_owned();
	pkcs11_engine_path.push(b'\0');

	let mut pkcs11_lib_path = std::os::unix::ffi::OsStrExt::as_bytes(pkcs11_lib_path.as_os_str()).to_owned();
	pkcs11_lib_path.push(b'\0');

	println!("Loading dynamic engine...");
	let mut engine = openssl2::StructuralEngine::by_id(std::ffi::CStr::from_bytes_with_nul(b"dynamic\0").unwrap())?;
	println!("Loaded engine: [{}]", engine.name()?.to_string_lossy());

	println!("Instructing dynamic engine to load libp11 engine...");
	engine.ctrl_cmd(
		std::ffi::CStr::from_bytes_with_nul(b"SO_PATH\0").unwrap(),
		0,
		std::ffi::CStr::from_bytes_with_nul(&pkcs11_engine_path).unwrap().as_ptr() as _,
		None,
		false,
	)?;
	engine.ctrl_cmd(
		std::ffi::CStr::from_bytes_with_nul(b"LOAD\0").unwrap(),
		0,
		std::ptr::null_mut(),
		None,
		false,
	)?;
	println!("Loaded engine: [{}]", engine.name()?.to_string_lossy());

	if verbose {
		engine.ctrl_cmd(
			std::ffi::CStr::from_bytes_with_nul(b"VERBOSE\0").unwrap(),
			0,
			std::ptr::null_mut(),
			None,
			false,
		)?;
	}
	else {
		engine.ctrl_cmd(
			std::ffi::CStr::from_bytes_with_nul(b"QUIET\0").unwrap(),
			0,
			std::ptr::null_mut(),
			None,
			false,
		)?;
	}

	println!("Instructing libp11 engine to load PKCS#11 library...");
	engine.ctrl_cmd(
		std::ffi::CStr::from_bytes_with_nul(b"MODULE_PATH\0").unwrap(),
		0,
		std::ffi::CStr::from_bytes_with_nul(&pkcs11_lib_path).unwrap().as_ptr() as _,
		None,
		false,
	)?;
	println!("Done");

	println!("Initializing structural engine to functional engine...");
	let engine = std::convert::TryInto::try_into(engine)?;
	println!("Done");

	Ok(engine)
}

fn load_public_key(
	engine: &mut openssl2::FunctionalEngine,
	key_id: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
	let mut key_id = key_id.into_bytes();
	key_id.push(b'\0');
	let key_id = std::ffi::CStr::from_bytes_with_nul(&key_id).unwrap();

	let key = engine.load_public_key(key_id)?;
	Ok(key)
}

fn load_private_key(
	engine: &mut openssl2::FunctionalEngine,
	key_id: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Error> {
	let mut key_id = key_id.into_bytes();
	key_id.push(b'\0');
	let key_id = std::ffi::CStr::from_bytes_with_nul(&key_id).unwrap();

	let key = engine.load_private_key(key_id)?;
	Ok(key)
}

struct Error(Box<dyn std::error::Error>, backtrace::Backtrace);

impl std::fmt::Debug for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "{}", self.0)?;

		let mut source = self.0.source();
		while let Some(err) = source {
			writeln!(f, "caused by: {}", err)?;
			source = err.source();
		}

		writeln!(f)?;

		writeln!(f, "{:?}", self.1)?;

		Ok(())
	}
}

impl<E> From<E> for Error where E: Into<Box<dyn std::error::Error>> {
	fn from(err: E) -> Self {
		Error(err.into(), Default::default())
	}
}

#[derive(structopt::StructOpt)]
struct Options {
	#[structopt(subcommand)]
	command: Command,

	/// Path of the libp11 engine library for openssl.
	#[structopt(long, default_value = "/usr/lib64/engines-1.1/pkcs11.so")]
	pkcs11_engine_path: std::path::PathBuf,

	/// Path of the PKCS#11 library.
	#[structopt(long, default_value = "/usr/lib64/softhsm/libsofthsm.so")]
	pkcs11_lib_path: std::path::PathBuf,

	/// Whether to use the OpenSC PKCS#11 Spy library to wrap around the actual PKCS#11 library specified by `--pkcs11-lib-path`
	///
	/// If specified but not given a value, defaults to "/usr/lib64/pkcs11/pkcs11-spy.so"
	#[allow(clippy::option_option)]
	#[structopt(long)]
	use_pkcs11_spy: Option<Option<std::path::PathBuf>>,

	/// Enables verbose logging from libp11.
	#[structopt(long)]
	verbose: bool,
}

#[derive(structopt::StructOpt)]
enum Command {
	/// Generate a CA cert.
	GenerateCaCert {
		/// The ID of the key pair of the CA, in a PKCS#11 URI format.
		#[structopt(long)]
		key: String,

		/// The path where the CA cert PEM file will be stored.
		#[structopt(long)]
		out_file: std::path::PathBuf,

		/// The subject CN of the new cert.
		#[structopt(long)]
		subject: String,
	},

	/// Generate a server auth cert.
	GenerateCert {
		#[structopt(long)]
		ca_cert: std::path::PathBuf,

		/// The ID of the key pair of the CA, in PKCS#11 URI format.
		#[structopt(long)]
		ca_key: String,

		/// The ID of the key pair of the server requesting the cert, in PKCS#11 URI format.
		#[structopt(long)]
		key: String,

		/// The path where the server cert PEM file will be stored.
		#[structopt(long)]
		out_file: std::path::PathBuf,

		/// The subject CN of the new cert.
		#[structopt(long)]
		subject: String,
	},

	/// Generate a key pair in the HSM.
	GenerateKeyPair {
		/// The ID of the token where the key pair will be stored, in a PKCS#11 URI format.
		///
		/// Must have either a `token` (label) or `slot-id` (slot ID) component to identify the slot,
		/// and a `pin-value` (user PIN) component.
		#[structopt(long)]
		key: String,

		/// The type of key pair to generate.
		#[structopt(long = "type", name = "type")] // Workaround for https://github.com/TeXitoi/structopt/issues/269
		#[structopt(possible_values = KEY_TYPE_VALUES)]
		r#type: KeyType,
	},

	/// Initializes a slot in the HSM. The slot is reinitialized if it was already previously initialized.
	InitializeSlot {
		/// The label that will be set on the slot.
		#[structopt(long)]
		label: String,

		/// The ID of the slot to initialize.
		#[structopt(long)]
		slot_id: pkcs11_sys::CK_SLOT_ID,

		/// The SO pin of the slot that will be initialized.
		///
		/// If the slot already exists and is being reinitialized, this must match the initial SO PIN used for the slot.
		#[structopt(long)]
		so_pin: String,

		/// The user pin that will be set on the slot.
		#[structopt(long)]
		user_pin: String,
	},

	/// Load one or more public keys from the HSM.
	Load {
		/// One or more IDs of public keys, each in PKCS#11 URI format. Each argument to the command is one key ID.
		#[structopt(long)]
		keys: Vec<String>,
	},

	/// Start a web server that uses the specified private key and cert file for TLS.
	WebServer {
		/// Path of the cert chain file.
		#[structopt(long)]
		cert: std::path::PathBuf,

		/// The ID of the key pair corresponding to the cert, in PKCS#11 URI format.
		#[structopt(long)]
		key: String,

		/// The port to listen on.
		#[structopt(long, default_value = "8443")]
		port: u16,
	},
}

const KEY_TYPE_VALUES: &[&str] = &[
	"ec-p256", "ec-p384", "ec-p521",
	#[cfg(ed25519)]
	"ec-ed25519",
	"rsa-2048", "rsa-4096",
];

enum KeyType {
	Ec(pkcs11::EcCurve),
	Rsa(pkcs11_sys::CK_ULONG),
}

impl std::str::FromStr for KeyType {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"ec-p256" => Ok(KeyType::Ec(pkcs11::EcCurve::NistP256)),
			"ec-p384" => Ok(KeyType::Ec(pkcs11::EcCurve::NistP384)),
			"ec-p521" => Ok(KeyType::Ec(pkcs11::EcCurve::NistP521)),
			#[cfg(ed25519)]
			"ec-ed25519" => Ok(KeyType::Ec(pkcs11::EcCurve::Ed25519)),
			"rsa-2048" => Ok(KeyType::Rsa(2048)),
			"rsa-4096" => Ok(KeyType::Rsa(4096)),
			s => Err(format!("unrecognized value [{}]", s)),
		}
	}
}

struct Displayable<T>(T);

/// In general, the public parameters of an EC key (point) cannot be obtained from the private key.
/// So depending on the underlying PKCS#11 library, an `EcKey<Private>` may not actually have information about the public parameters.
///
/// So only `EcKey<Public>` is displayable.
///
/// Unfortunately the typesystem does not help with this, because `EcKey<Public>` can be treated like an `EcKey<Private>`.
/// See <https://github.com/sfackler/rust-openssl/issues/1170>
impl std::fmt::Display for Displayable<openssl::ec::EcKey<openssl::pkey::Public>> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let group = self.0.group();
		let curve_name = group.curve_name().map(|nid| nid.long_name()).transpose()?.unwrap_or("<unknown>");

		let mut big_num_context = openssl::bn::BigNumContext::new()?;
		let point = self.0.public_key();
		let point = point.to_bytes(group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut big_num_context)?;

		write!(f, "curve = {}, point = 0x", curve_name)?;
		for b in point {
			write!(f, "{:02x}", b)?;
		}

		Ok(())
	}
}

/// The public parameters of an RSA key (modulus and exponent) can be obtained from the private key as well as the public key.
/// So both `Rsa<Private>` and `Rsa<Public>` are displayable.
impl<T> std::fmt::Display for Displayable<openssl::rsa::Rsa<T>> where T: openssl::pkey::HasPublic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let modulus = self.0.n();

		let exponent = self.0.e();

		write!(f, "modulus = 0x{} ({} bits), exponent = {}", modulus.to_hex_str()?, modulus.num_bits(), exponent)?;

		Ok(())
	}
}

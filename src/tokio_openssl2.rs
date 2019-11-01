pub(crate) fn connect(
	stream: std::net::TcpStream,
	cert_chain_path: &std::path::Path,
	private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
	domain: &str,
) -> std::io::Result<impl futures::Future<Item = hyper::Chunk, Error = std::io::Error>> {
	use futures::{Future, Stream};

	let stream = tokio::net::TcpStream::from_std(stream, &Default::default())?;

	let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;
	tls_connector.set_certificate_chain_file(cert_chain_path)?;
	tls_connector.set_private_key(private_key)?;

	// The root of the client cert is the CA, and we expect the server cert to be signed by this same CA.
	// So add it to the cert store.
	let ca_cert = {
		let cert_chain_file = std::fs::read(cert_chain_path)?;
		let mut cert_chain = openssl::x509::X509::stack_from_pem(&cert_chain_file)?;
		cert_chain.pop().unwrap()
	};
	tls_connector.cert_store_mut().add_cert(ca_cert)?;

	// Log the server cert chain. Does not change the verification result from what openssl already concluded.
	tls_connector.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |openssl_verification_result, context| {
		println!("Server cert:");
		let chain = context.chain().unwrap();
		for (i, cert) in chain.into_iter().enumerate() {
			println!("    #{}: {}", i + 1, cert.subject_name().entries().next().unwrap().data().as_utf8().unwrap());
		}
		println!("openssl verification result: {}", openssl_verification_result);
		openssl_verification_result
	});

	let tls_connector = tls_connector.build();

	Ok(tokio_openssl::SslConnectorExt::connect_async(&tls_connector, domain, stream)
		.then(|stream| -> std::io::Result<_> {
			let stream = stream.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			Ok(hyper::client::conn::handshake(stream).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err)))
		})
		.flatten()
		.and_then(|(mut send_request, connection)| {
			let mut request = hyper::Request::new(Default::default());
			*request.uri_mut() = hyper::Uri::from_static("/");
			let send_request = send_request.send_request(request);

			let connection = connection.without_shutdown();

			send_request.join(connection)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
		})
		.and_then(|(response, _)|
			response.into_body()
			.concat2()
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))))
}

/// A stream of incoming TLS connections, for use with a hyper server.
pub(crate) struct Incoming {
	listener: tokio::net::TcpListener,
	tls_acceptor: openssl::ssl::SslAcceptor,
	connections: futures::stream::futures_unordered::FuturesUnordered<tokio_openssl::AcceptAsync<tokio::net::TcpStream>>,
}

impl Incoming {
	pub(crate) fn new(
		listener: std::net::TcpListener,
		cert_chain_path: &std::path::Path,
		private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
	) -> std::io::Result<Self> {
		let listener = tokio::net::TcpListener::from_std(listener, &Default::default())?;

		let mut tls_acceptor = openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls())?;
		tls_acceptor.set_certificate_chain_file(cert_chain_path)?;
		tls_acceptor.set_private_key(private_key)?;

		// The root of the server cert is the CA, and we expect the client cert to be signed by this same CA.
		// So add it to the cert store.
		let ca_cert = {
			let cert_chain_file = std::fs::read(cert_chain_path)?;
			let mut cert_chain = openssl::x509::X509::stack_from_pem(&cert_chain_file)?;
			cert_chain.pop().unwrap()
		};
		tls_acceptor.cert_store_mut().add_cert(ca_cert)?;

		// Log the client cert chain. Does not change the verification result from what openssl already concluded.
		tls_acceptor.set_verify_callback(
			openssl::ssl::SslVerifyMode::PEER,
			|openssl_verification_result, context| {
				println!("Client cert:");
				let chain = context.chain().unwrap();
				for (i, cert) in chain.into_iter().enumerate() {
					println!("    #{}: {}", i + 1, cert.subject_name().entries().next().unwrap().data().as_utf8().unwrap());
				}
				println!("openssl verification result: {}", openssl_verification_result);
				openssl_verification_result
			});

		let tls_acceptor = tls_acceptor.build();

		Ok(Incoming {
			listener,
			tls_acceptor,
			connections: Default::default(),
		})
	}
}

impl futures::Stream for Incoming {
	type Item = tokio_openssl::SslStream<tokio::net::TcpStream>;
	type Error = std::io::Error;

	fn poll(&mut self) -> futures::Poll<Option<Self::Item>, Self::Error> {
		loop {
			match self.listener.poll_accept() {
				Ok(futures::Async::Ready((stream, _))) => {
					self.connections.push(tokio_openssl::SslAcceptorExt::accept_async(&self.tls_acceptor, stream));
				},

				Ok(futures::Async::NotReady) => break,

				Err(err) => eprintln!("Dropping client that failed to completely establish a TCP connection: {}", err),
			}
		}

		loop {
			if self.connections.is_empty() {
				return Ok(futures::Async::NotReady);
			}

			match self.connections.poll() {
				Ok(futures::Async::Ready(Some(stream))) => {
					println!("Accepted connection from client");
					return Ok(futures::Async::Ready(Some(stream)));
				},
				Ok(futures::Async::Ready(None)) => {
					println!("Shutting down web server");
					return Ok(futures::Async::Ready(None));
				},
				Ok(futures::Async::NotReady) => return Ok(futures::Async::NotReady),
				Err(err) => eprintln!("Dropping client that failed to complete a TLS handshake: {}", err),
			}
		}
	}
}

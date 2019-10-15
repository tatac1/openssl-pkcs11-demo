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

				Err(_) => eprintln!("Dropping client that failed to completely establish a TCP connection."),
			}
		}

		loop {
			if self.connections.is_empty() {
				return Ok(futures::Async::NotReady);
			}

			match self.connections.poll() {
				Ok(futures::Async::Ready(stream)) => return Ok(futures::Async::Ready(stream)),
				Ok(futures::Async::NotReady) => return Ok(futures::Async::NotReady),
				Err(_) => eprintln!("Dropping client that failed to complete a TLS handshake."),
			}
		}
	}
}

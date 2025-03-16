#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use crate::client::{tls::TlsPreloginWrapper, tls_stream::create_tls_stream};
#[cfg(feature = "aad")]
use crate::tds::codec::TokenFedAuthInfo;
use crate::{
    client::{tls::MaybeTlsStream, AuthMethod, Config},
    tds::{
        codec::{
            self, Encode, LoginMessage, Packet, PacketCodec, PacketHeader, PacketStatus,
            PreloginMessage, TokenDone,
        },
        stream::TokenStream,
        Context, HEADER_BYTES,
    },
    EncryptionLevel, SqlReadBytes,
};
use asynchronous_codec::Framed;
use bytes::BytesMut;
#[cfg(any(windows, feature = "integrated-auth-gssapi"))]
use codec::TokenSspi;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::ready;
use futures_util::sink::SinkExt;
use futures_util::stream::{Stream, TryStream, TryStreamExt};
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL},
};
use pretty_hex::*;
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use std::ops::Deref;
use std::{cmp, fmt::Debug, io, pin::Pin, task};
use task::Poll;
use tracing::{event, Level};
#[cfg(all(windows, feature = "winauth"))]
use winauth::{windows::NtlmSspiBuilder, NextBytes};

/// A `Connection` is an abstraction between the [`Client`] and the server. It
/// can be used as a `Stream` to fetch [`Packet`]s from and to `send` packets
/// splitting them to the negotiated limit automatically.
///
/// `Connection` is not meant to use directly, but as an abstraction layer for
/// the numerous `Stream`s for easy packet handling.
///
/// [`Client`]: struct.Encode.html
/// [`Packet`]: ../protocol/codec/struct.Packet.html
pub(crate) struct Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    transport: Framed<MaybeTlsStream<S>, PacketCodec>,
    flushed: bool,
    context: Context,
    buf: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("transport", &"Framed<..>")
            .field("flushed", &self.flushed)
            .field("context", &self.context)
            .field("buf", &self.buf.as_ref().hex_dump())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Creates a new connection
    pub(crate) async fn connect(config: Config, tcp_stream: S) -> crate::Result<Connection<S>> {
        let context = {
            let mut context = Context::new();
            context.set_spn(config.get_host(), config.get_port());
            context
        };

        let transport = Framed::new(MaybeTlsStream::Raw(tcp_stream), PacketCodec);

        let mut connection = Self {
            transport,
            context,
            flushed: false,
            buf: BytesMut::new(),
        };

        #[cfg(feature = "aad")]
        let fed_auth_required = matches!(
            config.auth,
            AuthMethod::AADToken(_) | AuthMethod::AADInteractive(_)
        );

        #[cfg(not(feature = "aad"))]
        let fed_auth_required = matches!(config.auth, AuthMethod::AADToken(_));

        let prelogin = connection
            .prelogin(config.encryption, fed_auth_required)
            .await?;

        let encryption = prelogin.negotiated_encryption(config.encryption);

        let connection = connection.tls_handshake(&config, encryption).await?;

        let mut connection = connection
            .login(
                config.auth,
                encryption,
                config.database,
                config.host,
                config.application_name,
                config.readonly,
                prelogin,
            )
            .await?;

        connection.flush_done().await?;

        Ok(connection)
    }

    /// Flush the incoming token stream until receiving `DONE` token.
    async fn flush_done(&mut self) -> crate::Result<TokenDone> {
        TokenStream::new(self).flush_done().await
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi"))]
    /// Flush the incoming token stream until receiving `SSPI` token.
    async fn flush_sspi(&mut self) -> crate::Result<TokenSspi> {
        TokenStream::new(self).flush_sspi().await
    }

    #[cfg(feature = "aad")]
    /// Flush the incoming token stream until receiving `FEDAUTHINFO` token.
    async fn flush_fed_auth_info(&mut self) -> crate::Result<TokenFedAuthInfo> {
        TokenStream::new(self).flush_fed_auth_info().await
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn post_login_encryption(mut self, encryption: EncryptionLevel) -> Self {
        if let EncryptionLevel::Off = encryption {
            event!(
                Level::WARN,
                "Turning TLS off after a login. All traffic from here on is not encrypted.",
            );

            let Self { transport, .. } = self;
            let tcp = transport.into_inner().into_inner();
            self.transport = Framed::new(MaybeTlsStream::Raw(tcp), PacketCodec);
        }

        self
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn post_login_encryption(self, _: EncryptionLevel) -> Self {
        self
    }

    /// Send an item to the wire. Header should define the item type and item should implement
    /// [`Encode`], defining the byte structure for the wire.
    ///
    /// The `send` will split the packet into multiple packets if bigger than
    /// the negotiated packet size, and handle flushing to the wire in an optimal way.
    ///
    /// [`Encode`]: ../protocol/codec/trait.Encode.html
    pub async fn send<E>(&mut self, mut header: PacketHeader, item: E) -> crate::Result<()>
    where
        E: Sized + Encode<BytesMut>,
    {
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        let mut payload = BytesMut::new();
        item.encode(&mut payload)?;

        while !payload.is_empty() {
            let writable = cmp::min(payload.len(), packet_size);
            let split_payload = payload.split_to(writable);

            if payload.is_empty() {
                header.set_status(PacketStatus::EndOfMessage);
            } else {
                header.set_status(PacketStatus::NormalMessage);
            }

            event!(
                Level::TRACE,
                "Sending a packet ({} bytes)",
                split_payload.len() + HEADER_BYTES,
            );

            self.write_to_wire(header, split_payload).await?;
        }

        self.flush_sink().await?;

        Ok(())
    }

    /// Sends a packet of data to the database.
    ///
    /// # Warning
    ///
    /// Please be sure the packet size doesn't exceed the largest allowed size
    /// dictaded by the server.
    pub(crate) async fn write_to_wire(
        &mut self,
        header: PacketHeader,
        data: BytesMut,
    ) -> crate::Result<()> {
        self.flushed = false;

        let packet = Packet::new(header, data);
        self.transport.send(packet).await?;

        Ok(())
    }

    /// Sends all pending packages to the wire.
    pub(crate) async fn flush_sink(&mut self) -> crate::Result<()> {
        self.transport.flush().await
    }

    /// Cleans the packet stream from previous use. It is important to use the
    /// whole stream before using the connection again. Flushing the stream
    /// makes sure we don't have any old data causing undefined behaviour after
    /// previous queries.
    ///
    /// Calling this will slow down the queries if stream is still dirty if all
    /// results are not handled.
    pub async fn flush_stream(&mut self) -> crate::Result<()> {
        self.buf.truncate(0);

        if self.flushed {
            return Ok(());
        }

        while let Some(packet) = self.try_next().await? {
            event!(
                Level::WARN,
                "Flushing unhandled packet from the wire. Please consume your streams!",
            );

            let is_last = packet.is_last();

            if is_last {
                break;
            }
        }

        Ok(())
    }

    /// True if the underlying stream has no more data and is consumed
    /// completely.
    pub fn is_eof(&self) -> bool {
        self.flushed && self.buf.is_empty()
    }

    /// A message sent by the client to set up context for login. The server
    /// responds to a client PRELOGIN message with a message of packet header
    /// type 0x04 and with the packet data containing a PRELOGIN structure.
    ///
    /// This message stream is also used to wrap the TLS handshake payload if
    /// encryption is needed. In this scenario, where PRELOGIN message is
    /// transporting the TLS handshake payload, the packet data is simply the
    /// raw bytes of the TLS handshake payload.
    async fn prelogin(
        &mut self,
        encryption: EncryptionLevel,
        fed_auth_required: bool,
    ) -> crate::Result<PreloginMessage> {
        let mut msg = PreloginMessage::new();
        msg.encryption = encryption;
        msg.fed_auth_required = fed_auth_required;

        let id = self.context.next_packet_id();
        self.send(PacketHeader::pre_login(id), msg).await?;

        let response: PreloginMessage = codec::collect_from(self).await?;
        dbg!(&response);
        // threadid (should be empty when sent from server to client)
        debug_assert_eq!(response.thread_id, 0);
        Ok(response)
    }

    /// Defines the login record rules with SQL Server. Authentication with
    /// connection options.
    #[allow(clippy::too_many_arguments)]
    async fn login<'a>(
        mut self,
        auth: AuthMethod,
        encryption: EncryptionLevel,
        db: Option<String>,
        server_name: Option<String>,
        application_name: Option<String>,
        readonly: bool,
        prelogin: PreloginMessage,
    ) -> crate::Result<Self> {
        let mut login_message = LoginMessage::new();

        if let Some(db) = db {
            login_message.db_name(db);
        }

        if let Some(server_name) = server_name {
            login_message.server_name(server_name);
        }

        if let Some(app_name) = application_name {
            login_message.app_name(app_name);
        }

        login_message.readonly(readonly);

        match auth {
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Integrated => {
                let mut client = NtlmSspiBuilder::new()
                    .target_spn(self.context.spn())
                    .build()?;

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::login(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => unreachable!(),
                }
            }
            #[cfg(all(unix, feature = "integrated-auth-gssapi"))]
            AuthMethod::Integrated => {
                let mut s = OidSet::new()?;
                s.add(&GSS_MECH_KRB5)?;

                let client_cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&s))?;

                let ctx = ClientCtx::new(
                    client_cred,
                    Name::new(self.context.spn().as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?,
                    CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                    None,
                );

                let init_token = ctx.step(None)?;

                login_message.integrated_security(Some(Vec::from(init_token.unwrap().deref())));

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let auth_bytes = self.flush_sspi().await?;

                let next_token = match ctx.step(Some(auth_bytes.as_ref()))? {
                    Some(response) => {
                        event!(Level::TRACE, response_len = response.len());
                        TokenSspi::new(Vec::from(response.deref()))
                    }
                    None => {
                        event!(Level::TRACE, response_len = 0);
                        TokenSspi::new(Vec::new())
                    }
                };

                let id = self.context.next_packet_id();
                let header = PacketHeader::login(id);

                self.send(header, next_token).await?;
            }
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Windows(auth) => {
                let spn = self.context.spn().to_string();
                let builder = winauth::NtlmV2ClientBuilder::new().target_spn(spn);
                let mut client = builder.build(auth.domain, auth.user, auth.password);

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::login(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => unreachable!(),
                }
            }
            AuthMethod::None => {
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::SqlServer(auth) => {
                login_message.user_name(auth.user());
                login_message.password(auth.password());

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::AADToken(token) => {
                login_message.aad_token(token, prelogin.fed_auth_required, prelogin.nonce);
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            #[cfg(feature = "aad")]
            AuthMethod::AADInteractive(auth) => {
                login_message.aad_interactive(prelogin.fed_auth_required);
                let id = self.context.next_packet_id();
                dbg!(&login_message);
                self.send(PacketHeader::login(id), login_message).await?;

                // federated authentication
                let fed_auth_info = self.flush_fed_auth_info().await?;
                dbg!(&fed_auth_info);
                self.authenticate_aad_interactive(&auth, &fed_auth_info)
                    .await?;
                self = self.post_login_encryption(encryption);
            }
        }

        Ok(self)
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    async fn tls_handshake(
        self,
        config: &Config,
        encryption: EncryptionLevel,
    ) -> crate::Result<Self> {
        if encryption != EncryptionLevel::NotSupported {
            event!(Level::INFO, "Performing a TLS handshake");

            let Self {
                transport, context, ..
            } = self;
            let mut stream = match transport.into_inner() {
                MaybeTlsStream::Raw(tcp) => {
                    create_tls_stream(config, TlsPreloginWrapper::new(tcp)).await?
                }
                _ => unreachable!(),
            };

            stream.get_mut().handshake_complete();
            event!(Level::INFO, "TLS handshake successful");

            let transport = Framed::new(MaybeTlsStream::Tls(stream), PacketCodec);

            Ok(Self {
                transport,
                context,
                flushed: false,
                buf: BytesMut::new(),
            })
        } else {
            event!(
                Level::WARN,
                "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
            );

            Ok(self)
        }
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    async fn tls_handshake(self, _: &Config, _: EncryptionLevel) -> crate::Result<Self> {
        event!(
            Level::WARN,
            "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
        );

        Ok(self)
    }

    pub(crate) async fn close(mut self) -> crate::Result<()> {
        self.transport.close().await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Stream for Connection<S> {
    type Item = crate::Result<Packet>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match ready!(this.transport.try_poll_next_unpin(cx)) {
            Some(Ok(packet)) => {
                this.flushed = packet.is_last();
                Poll::Ready(Some(Ok(packet)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> futures_util::io::AsyncRead for Connection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.get_mut();
        let size = buf.len();

        if this.buf.len() < size {
            while let Some(item) = ready!(Pin::new(&mut this).try_poll_next(cx)) {
                match item {
                    Ok(packet) => {
                        let (_, payload) = packet.into_parts();
                        this.buf.extend(payload);

                        if this.buf.len() >= size {
                            break;
                        }
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            e.to_string(),
                        )))
                    }
                }
            }

            // Got EOF before having all the data.
            if this.buf.len() < size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "No more packets in the wire",
                )));
            }
        }

        buf.copy_from_slice(this.buf.split_to(size).as_ref());
        Poll::Ready(Ok(size))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SqlReadBytes for Connection<S> {
    /// Hex dump of the current buffer.
    fn debug_buffer(&self) {
        dbg!(self.buf.as_ref().hex_dump());
    }

    /// The current execution context.
    fn context(&self) -> &Context {
        &self.context
    }

    /// A mutable reference to the current execution context.
    fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

#[cfg(feature = "aad")]
mod aad {
    use std::borrow::Cow;
    use std::error::Error;
    use std::sync::Arc;

    use futures_util::{AsyncRead, AsyncWrite};

    use crate::{
        client::AadAuth,
        tds::codec::{FedAuthToken, PacketHeader, TokenFedAuthInfo},
        Error as TdsError,
    };

    use super::Connection;

    const DEFAULT_SCOPE_SUFFIX: &str = "/.default";
    // Microsoft Entra ID client ID for public clients accessing Azure SQL
    const AAD_PUBLIC_CLIENT_ID: &str = "2fd908ad-0664-4344-b9be-cd3e8b574c38";
    const DEFAULT_HOST: &str = "localhost";
    const DEFAULT_PORT: u16 = 50968;

    impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
        /// Authenticate with Azure Active Directory using an interactive flow
        pub(super) async fn authenticate_aad_interactive(
            &mut self,
            auth: &AadAuth,
            fed_auth_info: &TokenFedAuthInfo,
        ) -> crate::Result<()> {
            let (sts_url, spn) = (fed_auth_info.sts_url(), fed_auth_info.spn());
            dbg!(sts_url, spn);

            let separator_index = sts_url.len()
                - 1
                - sts_url
                    .bytes()
                    .rev()
                    .position(|b| b == b'/')
                    .ok_or(TdsError::Protocol(
                        "Received an invalid sts_url in federated authentication info".into(),
                    ))?;
            let authority = &sts_url[..separator_index];
            let audience = &sts_url[separator_index + 1..];
            dbg!(&authority, &audience);

            let scope = Self::get_scope(spn);
            dbg!(&scope);

            // Get access token through interactive authentication
            match self
                .perform_interactive_auth(audience, &auth.user, &scope)
                .await
            {
                Ok(token) => {
                    // Send the token to the server
                    self.send_fed_auth_token(token).await
                }
                Err(e) => Err(TdsError::Protocol(
                    format!("Failed to perform interactive authentication: {}", e).into(),
                )),
            }
        }

        #[cfg(feature = "aad")]
        /// Performs interactive OAuth2 authentication with Azure AD using the PKCE flow
        async fn perform_interactive_auth(
            &self,
            tenant_id: &str,
            username: &str,
            scope: &str,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            use oauth2::basic::BasicClient;
            use oauth2::{
                AuthType, AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
                TokenUrl,
            };
            use oauth2::{AuthorizationCode, TokenResponse};
            use reqwest::{redirect, ClientBuilder};
            use std::net::{IpAddr, Ipv4Addr, SocketAddr};
            use tokio::net::TcpListener;
            use tokio::sync::Mutex;
            use tokio::time::{Duration, Instant};
            use url::Url;
            use uuid::Uuid;

            // Find an available port and create the server
            let port = Self::find_available_port()
                .await
                .ok_or("Could not find an available port")?;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let listener = TcpListener::bind(addr).await?;
            let redirect_url = format!("http://{}:{}", DEFAULT_HOST, port);
            tracing::info!("Using redirect URL: {}", redirect_url);
            tracing::info!("Local server bound to: {}:{}", DEFAULT_HOST, port);

            let client = BasicClient::new(ClientId::new(AAD_PUBLIC_CLIENT_ID.to_string()))
                .set_auth_uri(AuthUrl::new(format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                    tenant_id
                ))?)
                .set_token_uri(TokenUrl::new(format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    tenant_id
                ))?)
                .set_auth_type(AuthType::RequestBody)
                .set_redirect_uri(RedirectUrl::new(redirect_url)?);

            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            let state = CsrfToken::new(Uuid::new_v4().to_string());
            let csrf_state_str = state.secret().clone();

            // Generate the full authorization URL with all needed parameters
            let (auth_url, _csrf_state) = client
                .authorize_url(|| state)
                .add_scope(Scope::new(scope.to_string()))
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .add_scope(Scope::new("offline_access".to_string()))
                .set_pkce_challenge(pkce_challenge)
                .add_extra_param("login_hint", username)
                .add_extra_param("x-anchormailbox", format!("upn:{}", username))
                .add_extra_param("client-request-id", Uuid::new_v4().to_string())
                .add_extra_param("x-client-SKU", "Rust-OAuth2")
                .add_extra_param("x-client-Ver", "1.0.0")
                .add_extra_param("prompt", "select_account")
                .add_extra_param("client_info", "1")
                .url();

            tracing::info!("Opening browser to: {}", auth_url);

            // Open the browser with the authorization URL
            if let Err(e) = webbrowser::open(auth_url.as_str()) {
                tracing::warn!("Failed to open web browser: {}", e);
                tracing::warn!("Please manually navigate to: {}", auth_url);
            }

            // Create shared state for the authorization code
            let auth_code = Arc::new(Mutex::new(None));

            // Accept connections in a loop with timeout
            let timeout_duration = Duration::from_secs(120);
            let start_time = Instant::now();

            // Create a reqwest client without following redirects
            let http_client = ClientBuilder::new()
                .redirect(redirect::Policy::none())
                .build()?;

            // Accept connections in a loop with timeout
            while start_time.elapsed() < timeout_duration {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let auth_code_clone = Arc::clone(&auth_code);
                        let csrf_state = csrf_state_str.clone();

                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};

                            let mut socket = stream;
                            let mut buffer = [0; 4096];
                            let n = match socket.read(&mut buffer).await {
                                Ok(n) => n,
                                Err(e) => {
                                    tracing::error!("Failed to read from socket: {}", e);
                                    return;
                                }
                            };

                            let data = String::from_utf8_lossy(&buffer[..n]);

                            // Extract request line
                            let request_line = match data.lines().next() {
                                Some(line) => line,
                                None => return,
                            };

                            // Extract the path with query parameters
                            let path = match request_line.split_whitespace().nth(1) {
                                Some(path) => path,
                                None => return,
                            };

                            // Parse the query parameters
                            let query_string = match path.split('?').nth(1) {
                                Some(query) => query,
                                None => return,
                            };

                            // Parse the query string
                            let parsed_url =
                                match Url::parse(&format!("http://localhost/?{}", query_string)) {
                                    Ok(url) => url,
                                    Err(_) => return,
                                };

                            let pairs: Vec<_> = parsed_url.query_pairs().collect();

                            let code = pairs
                                .iter()
                                .find(|(k, _)| k == "code")
                                .map(|(_, v)| v.to_string());

                            let state = pairs
                                .iter()
                                .find(|(k, _)| k == "state")
                                .map(|(_, v)| v.to_string());

                            // Verify the state parameter to prevent CSRF attacks
                            if let Some(received_state) = state {
                                if received_state != csrf_state {
                                    let response = "HTTP/1.1 400 Bad Request\r\n\
                                                   Content-Type: text/plain\r\n\
                                                   \r\n\
                                                   Invalid state parameter, possible CSRF attack";
                                    let _ = socket.write_all(response.as_bytes()).await;
                                    return;
                                }
                            }

                            if let Some(code_value) = code {
                                // Store the authorization code
                                *auth_code_clone.lock().await = Some(code_value);

                                // Send a successful response to the browser
                                let response = "HTTP/1.1 200 OK\r\n\
                                               Content-Type: text/html\r\n\
                                               \r\n\
                                               <html><body><h1>Authentication successful!</h1>\
                                               <p>You can close this window and return to the application.</p></body></html>";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        });

                        // Check if we got the auth code
                        if auth_code.lock().await.is_some() {
                            break;
                        }
                    }
                    Err(e) => tracing::error!("Failed to accept connection: {}", e),
                }

                // A short sleep to avoid CPU spinning
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // Check if we timed out
            if start_time.elapsed() >= timeout_duration {
                return Err("Authentication timed out after 120 seconds".into());
            }

            // Get the authorization code
            let code = auth_code
                .lock()
                .await
                .clone()
                .ok_or("No authorization code received")?;

            tracing::info!("Received authorization code");

            let token_result = client
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(pkce_verifier)
                .request_async(&http_client)
                .await?;

            Ok(token_result.access_token().secret().to_string())
        }

        /// Constructs and sends the FEDAUTH token (0x08) with the provided access token.
        #[inline]
        async fn send_fed_auth_token(
            &mut self,
            access_token: impl AsRef<str>,
        ) -> crate::Result<()> {
            let fed_auth_token_message = FedAuthToken::new(access_token.as_ref());
            let id = self.context.next_packet_id();
            self.send(PacketHeader::fed_auth_token(id), fed_auth_token_message)
                .await?;
            Ok(())
        }

        /// Constructs a scope with suffix `/.default`.
        #[inline]
        fn get_scope(spn: &str) -> Cow<'_, str> {
            if spn.ends_with(DEFAULT_SCOPE_SUFFIX) {
                spn.into()
            } else {
                format!("{}{DEFAULT_SCOPE_SUFFIX}", spn.trim_end_matches('/')).into()
            }
        }

        /// Helper function to find an available port for the local server
        #[cfg(feature = "aad")]
        async fn find_available_port() -> Option<u16> {
            use std::net::{IpAddr, Ipv4Addr, SocketAddr};
            use tokio::net::TcpListener;

            let mut port = DEFAULT_PORT;
            while port < u16::MAX {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                if TcpListener::bind(addr).await.is_ok() {
                    return Some(port);
                }
                port += 1;
            }
            None
        }
    }
}

//! wolfSSL TLS integration for Tokio.
//!
//! wolfSSL performs the record I/O directly on the socket file descriptor. To stay correct with
//! Tokio's edge-triggered readiness, every wolfSSL call that may hit `EAGAIN` runs inside
//! [`TcpStream::try_io`]: Tokio then clears the readiness flag only if no new readiness event
//! arrived while the call ran, which avoids lost wake-ups.
//!
//! All `unsafe` code of the crate lives in this module and is limited to FFI calls on pointers
//! owned by [`SslHandle`] / [`WolfContext`].

use std::ffi::{c_char, c_int, c_short, c_void, CStr, CString};
use std::future::poll_fn;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll, Wake, Waker};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use tracing::info;

#[repr(C)]
pub struct WOLFSSL_CTX {
    _private: [u8; 0],
}

#[repr(C)]
pub struct WOLFSSL {
    _private: [u8; 0],
}

#[repr(C)]
pub struct WOLFSSL_METHOD {
    _private: [u8; 0],
}

#[repr(C)]
pub struct WOLFSSL_X509 {
    _private: [u8; 0],
}

const WOLFSSL_SUCCESS: c_int = 1;
const WOLFSSL_ERROR_WANT_READ: c_int = 2;
const WOLFSSL_ERROR_WANT_WRITE: c_int = 3;
const WOLFSSL_ERROR_ZERO_RETURN: c_int = 6;
const SSL_FILETYPE_PEM: c_int = 1;
const SSL_VERIFY_NONE: c_int = 0;
const SSL_VERIFY_PEER: c_int = 1;
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
const WOLFSSL_TLSV1_2: c_int = 3;
const WOLFSSL_ALPN_FAILED_ON_MISMATCH: u8 = 4;
const WOLFSSL_SNI_HOST_NAME: u8 = 0;
/// Smallest peer keys accepted (bits): below these, certificates are refused in the handshake.
const MIN_RSA_KEY_BITS: c_short = 2048;
const MIN_ECC_KEY_BITS: c_short = 256;

extern "C" {
    fn wolfSSL_Init() -> c_int;
    fn wolfTLSv1_3_server_method() -> *mut WOLFSSL_METHOD;
    fn wolfTLSv1_3_client_method() -> *mut WOLFSSL_METHOD;
    fn wolfSSLv23_server_method() -> *mut WOLFSSL_METHOD;
    fn wolfSSLv23_client_method() -> *mut WOLFSSL_METHOD;
    fn wolfSSL_CTX_new(method: *mut WOLFSSL_METHOD) -> *mut WOLFSSL_CTX;
    fn wolfSSL_CTX_free(ctx: *mut WOLFSSL_CTX);
    fn wolfSSL_CTX_use_certificate_chain_file(ctx: *mut WOLFSSL_CTX, file: *const c_char) -> c_int;
    fn wolfSSL_CTX_use_PrivateKey_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
        format: c_int,
    ) -> c_int;
    fn wolfSSL_CTX_load_verify_locations(
        ctx: *mut WOLFSSL_CTX,
        file: *const c_char,
        path: *const c_char,
    ) -> c_int;
    fn wolfSSL_CTX_set_verify(
        ctx: *mut WOLFSSL_CTX,
        mode: c_int,
        verify_callback: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
    );
    fn wolfSSL_CTX_SetMinVersion(ctx: *mut WOLFSSL_CTX, version: c_int) -> c_int;
    fn wolfSSL_CTX_set_cipher_list(ctx: *mut WOLFSSL_CTX, list: *const c_char) -> c_int;
    fn wolfSSL_CTX_SetMinRsaKey_Sz(ctx: *mut WOLFSSL_CTX, key_sz: c_short) -> c_int;
    fn wolfSSL_CTX_SetMinEccKey_Sz(ctx: *mut WOLFSSL_CTX, key_sz: c_short) -> c_int;
    fn wolfSSL_CTX_EnableCRL(ctx: *mut WOLFSSL_CTX, options: c_int) -> c_int;
    fn wolfSSL_CTX_LoadCRLFile(
        ctx: *mut WOLFSSL_CTX,
        path: *const c_char,
        file_type: c_int,
    ) -> c_int;
    fn wolfSSL_new(ctx: *mut WOLFSSL_CTX) -> *mut WOLFSSL;
    fn wolfSSL_free(ssl: *mut WOLFSSL);
    fn wolfSSL_set_fd(ssl: *mut WOLFSSL, fd: c_int) -> c_int;
    fn wolfSSL_UseALPN(ssl: *mut WOLFSSL, list: *mut c_char, list_sz: u32, options: u8) -> c_int;
    fn wolfSSL_UseSNI(ssl: *mut WOLFSSL, sni_type: u8, data: *const c_void, size: u16) -> c_int;
    fn wolfSSL_check_domain_name(ssl: *mut WOLFSSL, dn: *const c_char) -> c_int;
    fn wolfSSL_accept(ssl: *mut WOLFSSL) -> c_int;
    fn wolfSSL_connect(ssl: *mut WOLFSSL) -> c_int;
    fn wolfSSL_read(ssl: *mut WOLFSSL, data: *mut c_void, sz: c_int) -> c_int;
    fn wolfSSL_write(ssl: *mut WOLFSSL, data: *const c_void, sz: c_int) -> c_int;
    fn wolfSSL_shutdown(ssl: *mut WOLFSSL) -> c_int;
    fn wolfSSL_get_error(ssl: *mut WOLFSSL, ret: c_int) -> c_int;
    fn wolfSSL_get_peer_certificate(ssl: *mut WOLFSSL) -> *mut WOLFSSL_X509;
    fn wolfSSL_X509_get_subjectCN(x509: *mut WOLFSSL_X509) -> *mut c_char;
    fn wolfSSL_X509_get_next_altname(x509: *mut WOLFSSL_X509) -> *mut c_char;
    fn wolfSSL_X509_free(x509: *mut WOLFSSL_X509);
    fn wolfSSL_get_version(ssl: *const WOLFSSL) -> *const c_char;
}

/// The socket handle wolfSSL performs I/O on (`int` file descriptor / Winsock `SOCKET`).
#[cfg(unix)]
fn socket_handle(stream: &TcpStream) -> c_int {
    use std::os::unix::io::AsRawFd;
    stream.as_raw_fd()
}

#[cfg(windows)]
fn socket_handle(stream: &TcpStream) -> c_int {
    use std::os::windows::io::AsRawSocket;
    // wolfSSL_set_fd takes an int and casts it back to SOCKET; Winsock handles fit in 32 bits.
    stream.as_raw_socket() as c_int
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("{what} file not found: {path}")]
    FileNotFound { what: &'static str, path: String },
    #[error("failed to load {what} from {path}")]
    Load { what: &'static str, path: String },
    #[error("invalid TLS setting: {0}")]
    InvalidSetting(String),
    #[error("wolfSSL error: {0}")]
    Library(&'static str),
}

static WOLFSSL_INIT: std::sync::Once = std::sync::Once::new();

pub fn ensure_wolfssl_initialized() {
    WOLFSSL_INIT.call_once(|| {
        // SAFETY: global library initialization, guarded by `Once`.
        let ret = unsafe { wolfSSL_Init() };
        assert_eq!(
            ret, WOLFSSL_SUCCESS,
            "wolfSSL_Init failed with return code {ret}"
        );
        info!("wolfSSL cryptographic engine initialized");
    });
}

/// Owned `WOLFSSL_CTX`.
pub struct WolfContext {
    raw: NonNull<WOLFSSL_CTX>,
}

// SAFETY: a WOLFSSL_CTX is safe to share between threads once configured; it is only mutated
// during construction, before it is wrapped in an `Arc`.
unsafe impl Send for WolfContext {}
unsafe impl Sync for WolfContext {}

impl Drop for WolfContext {
    fn drop(&mut self) {
        // SAFETY: we own the context and no SSL object outlives it (they hold an Arc to it).
        unsafe { wolfSSL_CTX_free(self.raw.as_ptr()) };
    }
}

impl WolfContext {
    fn new(method: *mut WOLFSSL_METHOD) -> Result<Self, TlsError> {
        if method.is_null() {
            return Err(TlsError::Library("TLS method unavailable"));
        }
        // SAFETY: method is a valid static method table; wolfSSL_CTX_new takes ownership of it.
        let raw = unsafe { wolfSSL_CTX_new(method) };
        let ctx = NonNull::new(raw)
            .map(|raw| Self { raw })
            .ok_or(TlsError::Library("wolfSSL_CTX_new failed"))?;
        // SAFETY: ctx is valid.
        let ok = unsafe {
            wolfSSL_CTX_SetMinRsaKey_Sz(ctx.ptr(), MIN_RSA_KEY_BITS) == WOLFSSL_SUCCESS
                && wolfSSL_CTX_SetMinEccKey_Sz(ctx.ptr(), MIN_ECC_KEY_BITS) == WOLFSSL_SUCCESS
        };
        if !ok {
            return Err(TlsError::Library("setting minimum key sizes failed"));
        }
        Ok(ctx)
    }

    fn ptr(&self) -> *mut WOLFSSL_CTX {
        self.raw.as_ptr()
    }

    fn load_file(
        &self,
        what: &'static str,
        path: &str,
        f: impl FnOnce(*mut WOLFSSL_CTX, *const c_char) -> c_int,
    ) -> Result<(), TlsError> {
        if !Path::new(path).exists() {
            return Err(TlsError::FileNotFound {
                what,
                path: path.into(),
            });
        }
        let c_path = CString::new(path)
            .map_err(|_| TlsError::InvalidSetting(format!("{what} path contains NUL")))?;
        if f(self.ptr(), c_path.as_ptr()) != WOLFSSL_SUCCESS {
            return Err(TlsError::Load {
                what,
                path: path.into(),
            });
        }
        Ok(())
    }

    fn use_cert_chain(&self, path: &str, what: &'static str) -> Result<(), TlsError> {
        // SAFETY: ctx and the NUL-terminated path are valid for the duration of the call.
        self.load_file(what, path, |ctx, p| unsafe {
            wolfSSL_CTX_use_certificate_chain_file(ctx, p)
        })
    }

    fn use_private_key(&self, path: &str, what: &'static str) -> Result<(), TlsError> {
        // SAFETY: as above.
        self.load_file(what, path, |ctx, p| unsafe {
            wolfSSL_CTX_use_PrivateKey_file(ctx, p, SSL_FILETYPE_PEM)
        })
    }

    fn load_ca(&self, path: &str) -> Result<(), TlsError> {
        // SAFETY: as above; the directory argument may be NULL.
        self.load_file("CA certificate", path, |ctx, p| unsafe {
            wolfSSL_CTX_load_verify_locations(ctx, p, std::ptr::null())
        })
    }

    /// Checks client certificates against a certificate revocation list (PEM). Only the
    /// client's own certificate is checked; the CRL must be issued by the CA that signed it.
    fn load_crl(&self, path: &str) -> Result<(), TlsError> {
        // SAFETY: ctx is valid; 0 = check the peer certificate only.
        if unsafe { wolfSSL_CTX_EnableCRL(self.ptr(), 0) } != WOLFSSL_SUCCESS {
            return Err(TlsError::Library("wolfSSL_CTX_EnableCRL failed"));
        }
        // SAFETY: as for the other files.
        self.load_file("certificate revocation list", path, |ctx, p| unsafe {
            wolfSSL_CTX_LoadCRLFile(ctx, p, SSL_FILETYPE_PEM)
        })
    }

    fn set_verify(&self, mode: c_int) {
        // SAFETY: ctx is valid; no callback is installed.
        unsafe { wolfSSL_CTX_set_verify(self.ptr(), mode, None) };
    }

    fn set_cipher_list(&self, list: &str) -> Result<(), TlsError> {
        let normalized = list.replace(',', ":");
        let c = CString::new(normalized)
            .map_err(|_| TlsError::InvalidSetting("cipher list contains NUL".into()))?;
        // SAFETY: ctx and the NUL-terminated list are valid.
        if unsafe { wolfSSL_CTX_set_cipher_list(self.ptr(), c.as_ptr()) } != WOLFSSL_SUCCESS {
            return Err(TlsError::InvalidSetting(format!(
                "wolfSSL rejected cipher list '{list}'"
            )));
        }
        Ok(())
    }
}

/// Owned `WOLFSSL` session object. Freed exactly once, on drop.
struct SslHandle {
    raw: NonNull<WOLFSSL>,
    /// Keeps the context alive for as long as the session exists.
    _ctx: Arc<WolfContext>,
}

// SAFETY: a WOLFSSL object may move between threads; all access goes through `&mut self` of the
// owning stream, so it is never used concurrently.
unsafe impl Send for SslHandle {}

impl SslHandle {
    fn new(ctx: &Arc<WolfContext>) -> io::Result<Self> {
        // SAFETY: ctx is a valid, configured context.
        let raw = unsafe { wolfSSL_new(ctx.ptr()) };
        NonNull::new(raw)
            .map(|raw| Self {
                raw,
                _ctx: Arc::clone(ctx),
            })
            .ok_or_else(|| io::Error::other("wolfSSL_new failed"))
    }

    fn ptr(&self) -> *mut WOLFSSL {
        self.raw.as_ptr()
    }

    fn error(&self, ret: c_int) -> c_int {
        // SAFETY: ssl is valid.
        unsafe { wolfSSL_get_error(self.ptr(), ret) }
    }
}

impl Drop for SslHandle {
    fn drop(&mut self) {
        // SAFETY: we own the object and it is not used after this point.
        unsafe { wolfSSL_free(self.ptr()) };
    }
}

/// Builds the comma separated ALPN list wolfSSL expects.
fn alpn_list(protocols: &[String]) -> Result<Option<CString>, TlsError> {
    if protocols.is_empty() {
        return Ok(None);
    }
    if protocols
        .iter()
        .any(|p| p.is_empty() || p.contains([',', '\0']))
    {
        return Err(TlsError::InvalidSetting(
            "invalid ALPN protocol name".into(),
        ));
    }
    CString::new(protocols.join(","))
        .map(Some)
        .map_err(|_| TlsError::InvalidSetting("invalid ALPN protocol name".into()))
}

/// Which half of a split stream is polling (see [`DirectionWaiters`]).
#[derive(Clone, Copy)]
enum Role {
    Reader = 0,
    Writer = 1,
}

/// Wakers of every task waiting for one readiness direction of the socket.
///
/// Tokio remembers only the most recent waker per direction. After `tokio::io::split`, a read
/// may need the socket to be writable (wolfSSL answering a TLS 1.3 KeyUpdate) while the writer
/// half waits for writability too; registering the reader's waker would silently drop the
/// writer's. Tokio is therefore given one proxy waker per direction that wakes all waiters.
#[derive(Default)]
struct DirectionWaiters {
    waiters: Mutex<[Option<Waker>; 2]>,
}

impl DirectionWaiters {
    fn register(&self, role: Role, waker: &Waker) {
        let mut w = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        let slot = &mut w[role as usize];
        if !slot.as_ref().is_some_and(|old| old.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }
}

impl Wake for DirectionWaiters {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.waiters.lock().unwrap_or_else(|e| e.into_inner()));
        for w in waiters.into_iter().flatten() {
            w.wake();
        }
    }
}

struct Readiness {
    read: Arc<DirectionWaiters>,
    write: Arc<DirectionWaiters>,
    read_proxy: Waker,
    write_proxy: Waker,
}

impl Readiness {
    fn new() -> Self {
        let read = Arc::new(DirectionWaiters::default());
        let write = Arc::new(DirectionWaiters::default());
        Self {
            read_proxy: Waker::from(Arc::clone(&read)),
            write_proxy: Waker::from(Arc::clone(&write)),
            read,
            write,
        }
    }
}

/// Outcome of one wolfSSL operation attempt.
enum Step {
    Done(c_int),
    Want(Interest),
    Eof,
    Fatal(c_int),
}

/// TLS stream over a Tokio TCP socket.
pub struct WolfTlsStream {
    // Field order matters: the SSL object is freed before the socket is closed.
    ssl: SslHandle,
    stream: TcpStream,
    readiness: Readiness,
    shutdown_sent: bool,
}

impl WolfTlsStream {
    fn new(ctx: &Arc<WolfContext>, stream: TcpStream) -> io::Result<Self> {
        let ssl = SslHandle::new(ctx)?;
        // SAFETY: ssl is valid and the fd stays open as long as `stream` (owned by Self) lives.
        if unsafe { wolfSSL_set_fd(ssl.ptr(), socket_handle(&stream)) } != WOLFSSL_SUCCESS {
            return Err(io::Error::other("wolfSSL_set_fd failed"));
        }
        Ok(Self {
            ssl,
            stream,
            readiness: Readiness::new(),
            shutdown_sent: false,
        })
    }

    fn classify(&self, ret: c_int) -> Step {
        if ret > 0 {
            return Step::Done(ret);
        }
        match self.ssl.error(ret) {
            WOLFSSL_ERROR_WANT_READ => Step::Want(Interest::READABLE),
            WOLFSSL_ERROR_WANT_WRITE => Step::Want(Interest::WRITABLE),
            WOLFSSL_ERROR_ZERO_RETURN => Step::Eof,
            _ if ret == 0 => Step::Eof,
            err => Step::Fatal(err),
        }
    }

    /// Drives a wolfSSL operation to completion, registering for socket readiness as needed.
    fn poll_op(
        &mut self,
        cx: &mut Context<'_>,
        role: Role,
        mut op: impl FnMut(*mut WOLFSSL) -> c_int,
    ) -> Poll<io::Result<Option<c_int>>> {
        // Optimistic attempt: wolfSSL may complete from its internal buffers without the socket.
        let mut want = match self.classify(op(self.ssl.ptr())) {
            Step::Done(n) => return Poll::Ready(Ok(Some(n))),
            Step::Eof => return Poll::Ready(Ok(None)),
            Step::Fatal(err) => {
                return Poll::Ready(Err(io::Error::other(format!("wolfSSL error {err}"))))
            }
            Step::Want(interest) => interest,
        };
        loop {
            if want == Interest::READABLE {
                self.readiness.read.register(role, cx.waker());
                let mut proxy = Context::from_waker(&self.readiness.read_proxy);
                ready!(self.stream.poll_read_ready(&mut proxy))?;
            } else {
                self.readiness.write.register(role, cx.waker());
                let mut proxy = Context::from_waker(&self.readiness.write_proxy);
                ready!(self.stream.poll_write_ready(&mut proxy))?;
            }
            let ssl = self.ssl.ptr();
            let this = &*self;
            let attempt = this.stream.try_io(want, || match this.classify(op(ssl)) {
                // Clears readiness for `want` (only if no new event raced in) and retries.
                Step::Want(i) if i == want => Err(io::ErrorKind::WouldBlock.into()),
                other => Ok(other),
            });
            match attempt {
                Ok(Step::Done(n)) => return Poll::Ready(Ok(Some(n))),
                Ok(Step::Eof) => return Poll::Ready(Ok(None)),
                Ok(Step::Fatal(err)) => {
                    return Poll::Ready(Err(io::Error::other(format!("wolfSSL error {err}"))))
                }
                Ok(Step::Want(other)) => want = other,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    async fn handshake(&mut self, server: bool) -> io::Result<()> {
        let result = poll_fn(|cx| {
            self.poll_op(cx, Role::Writer, |ssl| {
                // SAFETY: ssl is valid for the lifetime of self.
                unsafe {
                    if server {
                        wolfSSL_accept(ssl)
                    } else {
                        wolfSSL_connect(ssl)
                    }
                }
            })
        })
        .await?;
        match result {
            Some(_) => Ok(()),
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "peer closed during TLS handshake",
            )),
        }
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }

    /// Negotiated protocol version, e.g. "TLSv1.3".
    pub fn protocol_version(&self) -> String {
        // SAFETY: returns a pointer to a static string or NULL.
        let p = unsafe { wolfSSL_get_version(self.ssl.ptr()) };
        if p.is_null() {
            return String::new();
        }
        // SAFETY: non-null, NUL-terminated static string.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// Subject CN and subject alternative names of the verified peer certificate.
    pub fn peer_identities(&self) -> Vec<String> {
        // SAFETY: returns an owned duplicate (or NULL) that we free below.
        let cert = unsafe { wolfSSL_get_peer_certificate(self.ssl.ptr()) };
        if cert.is_null() {
            return Vec::new();
        }
        let mut ids = Vec::new();
        // SAFETY: cert is valid until freed; returned strings point into it.
        unsafe {
            let cn = wolfSSL_X509_get_subjectCN(cert);
            if !cn.is_null() {
                ids.push(CStr::from_ptr(cn).to_string_lossy().into_owned());
            }
            loop {
                let alt = wolfSSL_X509_get_next_altname(cert);
                if alt.is_null() {
                    break;
                }
                ids.push(CStr::from_ptr(alt).to_string_lossy().into_owned());
            }
            wolfSSL_X509_free(cert);
        }
        ids.retain(|s| !s.is_empty());
        ids
    }
}

impl AsyncRead for WolfTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        if unfilled.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let len = unfilled.len().min(c_int::MAX as usize) as c_int;
        let ptr = unfilled.as_mut_ptr();
        // SAFETY: `ptr` points to `len` writable bytes owned by `buf` for this call.
        let n = ready!(this.poll_op(cx, Role::Reader, |ssl| unsafe {
            wolfSSL_read(ssl, ptr.cast(), len)
        }))?;
        if let Some(n) = n {
            buf.advance(n as usize);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WolfTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let len = buf.len().min(c_int::MAX as usize) as c_int;
        // SAFETY: `buf` is readable for `len` bytes; wolfSSL requires the same buffer on retry,
        // which AsyncWrite callers provide.
        let n = ready!(this.poll_op(cx, Role::Writer, |ssl| unsafe {
            wolfSSL_write(ssl, buf.as_ptr().cast(), len)
        }))?;
        match n {
            Some(n) => Poll::Ready(Ok(n as usize)),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // wolfSSL_write only returns once the record has been handed to the kernel.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown_sent {
            this.shutdown_sent = true;
            // Best effort close_notify; the peer's reply is not awaited.
            // SAFETY: ssl is valid.
            let _ = unsafe { wolfSSL_shutdown(this.ssl.ptr()) };
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

/// Minimum TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// Server-side TLS settings.
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub cert_file: String,
    pub key_file: String,
    /// CA used to verify client certificates; `Some` enables mutual TLS.
    pub client_ca_file: Option<String>,
    /// Certificate revocation list for client certificates (mutual TLS only).
    pub crl_file: Option<String>,
    pub min_version: TlsVersion,
    pub ciphers: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub handshake_timeout: Duration,
}

impl TlsServerConfig {
    pub fn new(cert_file: impl Into<String>, key_file: impl Into<String>) -> Self {
        Self {
            cert_file: cert_file.into(),
            key_file: key_file.into(),
            client_ca_file: None,
            crl_file: None,
            min_version: TlsVersion::Tls13,
            ciphers: None,
            alpn_protocols: vec!["mqtt".into()],
            handshake_timeout: Duration::from_secs(10),
        }
    }

    pub fn from_config(c: &crate::config::WolfTlsConfig) -> Self {
        Self {
            cert_file: c.server_cert_file.clone(),
            key_file: c.server_key_file.clone(),
            client_ca_file: c.require_client_cert.then(|| c.ca_cert_file.clone()),
            crl_file: (c.require_client_cert && !c.crl_file.is_empty()).then(|| c.crl_file.clone()),
            min_version: if c.min_tls_version == "TLSv1.2" {
                TlsVersion::Tls12
            } else {
                TlsVersion::Tls13
            },
            ciphers: (!c.ciphers.is_empty()).then(|| c.ciphers.clone()),
            alpn_protocols: c.alpn_protocols.clone(),
            handshake_timeout: Duration::from_secs(c.handshake_timeout_sec.max(1)),
        }
    }
}

#[derive(Clone)]
pub struct WolfTlsAcceptor {
    ctx: Arc<WolfContext>,
    alpn: Option<Arc<CString>>,
    handshake_timeout: Duration,
    mutual: bool,
}

impl WolfTlsAcceptor {
    /// Performs the server handshake, bounded by the configured handshake timeout.
    pub async fn accept(&self, stream: TcpStream) -> io::Result<WolfTlsStream> {
        let mut tls = WolfTlsStream::new(&self.ctx, stream)?;
        if let Some(alpn) = &self.alpn {
            let mut list = alpn.as_bytes().to_vec();
            let len = list.len() as u32;
            list.push(0);
            // SAFETY: ssl is valid; wolfSSL copies the list during the call.
            let rc = unsafe {
                wolfSSL_UseALPN(
                    tls.ssl.ptr(),
                    list.as_mut_ptr().cast(),
                    len,
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH,
                )
            };
            if rc != WOLFSSL_SUCCESS {
                return Err(io::Error::other("wolfSSL_UseALPN failed"));
            }
        }
        match tokio::time::timeout(self.handshake_timeout, tls.handshake(true)).await {
            Ok(Ok(())) => Ok(tls),
            Ok(Err(e)) => Err(e),
            // Dropping `tls` here frees the half-finished SSL object.
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake timeout",
            )),
        }
    }

    /// True when client certificates are required and verified.
    pub fn is_mutual(&self) -> bool {
        self.mutual
    }
}

/// Creates the wolfSSL acceptor used by the TLS listener.
pub fn create_tls_acceptor(cfg: &TlsServerConfig) -> Result<WolfTlsAcceptor, TlsError> {
    ensure_wolfssl_initialized();
    // SAFETY: method constructors return pointers to static tables.
    let method = unsafe {
        match cfg.min_version {
            TlsVersion::Tls13 => wolfTLSv1_3_server_method(),
            TlsVersion::Tls12 => wolfSSLv23_server_method(),
        }
    };
    let ctx = WolfContext::new(method)?;
    if cfg.min_version == TlsVersion::Tls12 {
        // SAFETY: ctx is valid.
        if unsafe { wolfSSL_CTX_SetMinVersion(ctx.ptr(), WOLFSSL_TLSV1_2) } != WOLFSSL_SUCCESS {
            return Err(TlsError::Library("wolfSSL_CTX_SetMinVersion failed"));
        }
    }
    ctx.use_cert_chain(&cfg.cert_file, "server certificate")?;
    ctx.use_private_key(&cfg.key_file, "server private key")?;
    match &cfg.client_ca_file {
        Some(ca) => {
            ctx.load_ca(ca)?;
            ctx.set_verify(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
            if let Some(crl) = &cfg.crl_file {
                ctx.load_crl(crl)?;
            }
        }
        None => ctx.set_verify(SSL_VERIFY_NONE),
    }
    if let Some(ciphers) = &cfg.ciphers {
        ctx.set_cipher_list(ciphers)?;
    }
    Ok(WolfTlsAcceptor {
        ctx: Arc::new(ctx),
        alpn: alpn_list(&cfg.alpn_protocols)?.map(Arc::new),
        handshake_timeout: cfg.handshake_timeout,
        mutual: cfg.client_ca_file.is_some(),
    })
}

#[derive(Clone)]
pub struct WolfTlsConnector {
    ctx: Arc<WolfContext>,
    alpn: Option<Arc<CString>>,
}

impl WolfTlsConnector {
    /// Connects, sending SNI and verifying that the server certificate matches `domain`.
    pub async fn connect(&self, domain: &str, stream: TcpStream) -> io::Result<WolfTlsStream> {
        let c_domain = CString::new(domain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain contains NUL"))?;
        let mut tls = WolfTlsStream::new(&self.ctx, stream)?;
        let ssl = tls.ssl.ptr();
        if !domain.is_empty() {
            let len = u16::try_from(c_domain.as_bytes().len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain too long"))?;
            // SAFETY: ssl is valid; the domain buffer holds `len` bytes and wolfSSL copies it.
            unsafe {
                if wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, c_domain.as_ptr().cast(), len)
                    != WOLFSSL_SUCCESS
                {
                    return Err(io::Error::other("wolfSSL_UseSNI failed"));
                }
                if wolfSSL_check_domain_name(ssl, c_domain.as_ptr()) != WOLFSSL_SUCCESS {
                    return Err(io::Error::other("wolfSSL_check_domain_name failed"));
                }
            }
        }
        if let Some(alpn) = &self.alpn {
            let mut list = alpn.as_bytes().to_vec();
            let len = list.len() as u32;
            list.push(0);
            // SAFETY: as in the acceptor.
            let rc = unsafe {
                wolfSSL_UseALPN(
                    ssl,
                    list.as_mut_ptr().cast(),
                    len,
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH,
                )
            };
            if rc != WOLFSSL_SUCCESS {
                return Err(io::Error::other("wolfSSL_UseALPN failed"));
            }
        }
        tls.handshake(false).await?;
        Ok(tls)
    }
}

/// Creates a wolfSSL connector (used by the benchmark, simulator and tests).
/// Verifies the server against `ca_cert_path`; optionally presents a client certificate.
pub fn create_tls_connector(
    ca_cert_path: &str,
    client_cert_and_key: Option<(&str, &str)>,
) -> Result<WolfTlsConnector, TlsError> {
    ensure_wolfssl_initialized();
    // SAFETY: static method table.
    let ctx = WolfContext::new(unsafe { wolfTLSv1_3_client_method() })?;
    ctx.load_ca(ca_cert_path)?;
    ctx.set_verify(SSL_VERIFY_PEER);
    if let Some((cert, key)) = client_cert_and_key {
        ctx.use_cert_chain(cert, "client certificate")?;
        ctx.use_private_key(key, "client private key")?;
    }
    Ok(WolfTlsConnector {
        ctx: Arc::new(ctx),
        alpn: alpn_list(&["mqtt".to_string()])?.map(Arc::new),
    })
}

/// Creates a connector that accepts TLS 1.2 or 1.3 servers.
pub fn create_tls12_connector(ca_cert_path: &str) -> Result<WolfTlsConnector, TlsError> {
    ensure_wolfssl_initialized();
    // SAFETY: static method table.
    let ctx = WolfContext::new(unsafe { wolfSSLv23_client_method() })?;
    ctx.load_ca(ca_cert_path)?;
    ctx.set_verify(SSL_VERIFY_PEER);
    Ok(WolfTlsConnector {
        ctx: Arc::new(ctx),
        alpn: None,
    })
}

pub type TlsAcceptor = WolfTlsAcceptor;
pub type TlsConnector = WolfTlsConnector;
pub type TlsStream = WolfTlsStream;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_list_validation() {
        assert!(alpn_list(&[]).unwrap().is_none());
        assert_eq!(
            alpn_list(&["mqtt".into(), "x-amzn-mqtt-ca".into()])
                .unwrap()
                .unwrap()
                .to_str()
                .unwrap(),
            "mqtt,x-amzn-mqtt-ca"
        );
        assert!(alpn_list(&["a,b".into()]).is_err());
        assert!(alpn_list(&["".into()]).is_err());
    }

    #[test]
    fn missing_files_are_reported() {
        let cfg = TlsServerConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(matches!(
            create_tls_acceptor(&cfg),
            Err(TlsError::FileNotFound { .. })
        ));
    }
}

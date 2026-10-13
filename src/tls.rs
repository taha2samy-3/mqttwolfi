use std::ffi::CString;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
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

pub const WOLFSSL_SUCCESS: i32 = 1;
pub const WOLFSSL_FAILURE: i32 = 0;
pub const WOLFSSL_ERROR_WANT_READ: i32 = 2;
pub const WOLFSSL_ERROR_WANT_WRITE: i32 = 3;
pub const WOLFSSL_ERROR_ZERO_RETURN: i32 = 6;

pub const SSL_FILETYPE_PEM: i32 = 1;
pub const SSL_VERIFY_NONE: i32 = 0;
pub const SSL_VERIFY_PEER: i32 = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: i32 = 2;

extern "C" {
    pub fn wolfSSL_Init() -> i32;
    pub fn wolfSSL_Cleanup() -> i32;

    pub fn wolfTLSv1_3_server_method() -> *mut WOLFSSL_METHOD;
    pub fn wolfTLSv1_3_client_method() -> *mut WOLFSSL_METHOD;
    pub fn wolfSSLv23_server_method() -> *mut WOLFSSL_METHOD;
    pub fn wolfSSLv23_client_method() -> *mut WOLFSSL_METHOD;

    pub fn wolfSSL_CTX_new(method: *mut WOLFSSL_METHOD) -> *mut WOLFSSL_CTX;
    pub fn wolfSSL_CTX_free(ctx: *mut WOLFSSL_CTX);

    pub fn wolfSSL_CTX_use_certificate_chain_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const std::ffi::c_char,
    ) -> i32;

    pub fn wolfSSL_CTX_use_PrivateKey_file(
        ctx: *mut WOLFSSL_CTX,
        file: *const std::ffi::c_char,
        format: i32,
    ) -> i32;

    pub fn wolfSSL_CTX_load_verify_locations(
        ctx: *mut WOLFSSL_CTX,
        file: *const std::ffi::c_char,
        path: *const std::ffi::c_char,
    ) -> i32;

    pub fn wolfSSL_CTX_set_verify(
        ctx: *mut WOLFSSL_CTX,
        mode: i32,
        verify_callback: Option<extern "C" fn(i32, *mut std::ffi::c_void) -> i32>,
    );

    pub fn wolfSSL_new(ctx: *mut WOLFSSL_CTX) -> *mut WOLFSSL;
    pub fn wolfSSL_free(ssl: *mut WOLFSSL);
    pub fn wolfSSL_set_fd(ssl: *mut WOLFSSL, fd: i32) -> i32;

    pub fn wolfSSL_UseALPN(
        ssl: *mut WOLFSSL,
        protocol_name_list: *const std::ffi::c_char,
        protocol_name_list_sz: u32,
        options: u8,
    ) -> i32;

    pub fn wolfSSL_UseSNI(
        ssl: *mut WOLFSSL,
        sni_type: u8,
        data: *const std::ffi::c_void,
        size: u16,
    ) -> i32;

    pub fn wolfSSL_accept(ssl: *mut WOLFSSL) -> i32;
    pub fn wolfSSL_connect(ssl: *mut WOLFSSL) -> i32;
    pub fn wolfSSL_read(ssl: *mut WOLFSSL, data: *mut std::ffi::c_void, sz: i32) -> i32;
    pub fn wolfSSL_write(ssl: *mut WOLFSSL, data: *const std::ffi::c_void, sz: i32) -> i32;
    pub fn wolfSSL_shutdown(ssl: *mut WOLFSSL) -> i32;
    pub fn wolfSSL_get_error(ssl: *mut WOLFSSL, ret: i32) -> i32;
    pub fn wolfSSL_pending(ssl: *mut WOLFSSL) -> i32;
}

static WOLFSSL_INIT: std::sync::Once = std::sync::Once::new();

pub fn ensure_wolfssl_initialized() {
    WOLFSSL_INIT.call_once(|| {
        let ret = unsafe { wolfSSL_Init() };
        if ret != WOLFSSL_SUCCESS {
            panic!("wolfSSL_Init failed with return code {}", ret);
        }
        info!("Native wolfSSL 5.9+ cryptographic engine initialized successfully");
    });
}

pub struct WolfContext {
    raw: *mut WOLFSSL_CTX,
}

unsafe impl Send for WolfContext {}
unsafe impl Sync for WolfContext {}

impl Drop for WolfContext {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { wolfSSL_CTX_free(self.raw) };
        }
    }
}

impl WolfContext {
    pub fn as_ptr(&self) -> *mut WOLFSSL_CTX {
        self.raw
    }
}

#[derive(Clone)]
pub struct WolfTlsAcceptor {
    ctx: Arc<WolfContext>,
}

impl WolfTlsAcceptor {
    pub async fn accept(&self, stream: TcpStream) -> io::Result<WolfTlsStream> {
        WolfTlsStream::accept(stream, &self.ctx).await
    }
}

#[derive(Clone)]
pub struct WolfTlsConnector {
    ctx: Arc<WolfContext>,
}

impl WolfTlsConnector {
    pub async fn connect<T>(&self, domain: T, stream: TcpStream) -> io::Result<WolfTlsStream>
    where
        T: ToString,
    {
        let domain_str = domain.to_string();
        WolfTlsStream::connect(&domain_str, stream, &self.ctx).await
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct WolfSslPtr(pub *mut WOLFSSL);

unsafe impl Send for WolfSslPtr {}
unsafe impl Sync for WolfSslPtr {}

pub struct WolfTlsStream {
    ssl: Arc<Mutex<WolfSslPtr>>,
    stream: TcpStream,
}

unsafe impl Send for WolfTlsStream {}
unsafe impl Sync for WolfTlsStream {}

impl Drop for WolfTlsStream {
    fn drop(&mut self) {
        if Arc::strong_count(&self.ssl) == 1 {
            let guard = self.ssl.lock().unwrap();
            if !guard.0.is_null() {
                unsafe {
                    let _ = wolfSSL_shutdown(guard.0);
                    wolfSSL_free(guard.0);
                }
            }
        }
    }
}

impl WolfTlsStream {
    pub async fn accept(stream: TcpStream, ctx: &Arc<WolfContext>) -> io::Result<Self> {
        let raw_ssl = unsafe { wolfSSL_new(ctx.as_ptr()) };
        if raw_ssl.is_null() {
            return Err(io::Error::other("wolfSSL_new failed"));
        }

        // Set ALPN "mqtt"
        let alpn = b"mqtt\0";
        unsafe {
            wolfSSL_UseALPN(raw_ssl, alpn.as_ptr() as *const _, 4, 4);
        }

        let fd = stream.as_raw_fd();
        if unsafe { wolfSSL_set_fd(raw_ssl, fd) } != WOLFSSL_SUCCESS {
            unsafe { wolfSSL_free(raw_ssl) };
            return Err(io::Error::other("wolfSSL_set_fd failed"));
        }

        let ssl = Arc::new(Mutex::new(WolfSslPtr(raw_ssl)));

        loop {
            let ret = {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_accept(guard.0) }
            };
            if ret == WOLFSSL_SUCCESS {
                break;
            }
            let err = {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_get_error(guard.0, ret) }
            };
            if err == WOLFSSL_ERROR_WANT_READ {
                let _: io::Result<()> = stream.try_io(Interest::READABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                stream.readable().await?;
            } else if err == WOLFSSL_ERROR_WANT_WRITE {
                let _: io::Result<()> = stream.try_io(Interest::WRITABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                stream.writable().await?;
            } else {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_free(guard.0) };
                return Err(io::Error::other(format!(
                    "wolfSSL_accept failed with error code: {}",
                    err
                )));
            }
        }

        Ok(Self { ssl, stream })
    }

    pub async fn connect(
        domain: &str,
        stream: TcpStream,
        ctx: &Arc<WolfContext>,
    ) -> io::Result<Self> {
        let raw_ssl = unsafe { wolfSSL_new(ctx.as_ptr()) };
        if raw_ssl.is_null() {
            return Err(io::Error::other("wolfSSL_new failed"));
        }

        // Set SNI Hostname
        if !domain.is_empty() {
            let c_domain = CString::new(domain).unwrap_or_default();
            unsafe {
                wolfSSL_UseSNI(
                    raw_ssl,
                    0,
                    c_domain.as_ptr() as *const _,
                    domain.len() as u16,
                );
            }
        }

        // Set ALPN "mqtt"
        let alpn = b"mqtt\0";
        unsafe {
            wolfSSL_UseALPN(raw_ssl, alpn.as_ptr() as *const _, 4, 4);
        }

        let fd = stream.as_raw_fd();
        if unsafe { wolfSSL_set_fd(raw_ssl, fd) } != WOLFSSL_SUCCESS {
            unsafe { wolfSSL_free(raw_ssl) };
            return Err(io::Error::other("wolfSSL_set_fd failed"));
        }

        let ssl = Arc::new(Mutex::new(WolfSslPtr(raw_ssl)));

        loop {
            let ret = {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_connect(guard.0) }
            };
            if ret == WOLFSSL_SUCCESS {
                break;
            }
            let err = {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_get_error(guard.0, ret) }
            };
            if err == WOLFSSL_ERROR_WANT_READ {
                let _: io::Result<()> = stream.try_io(Interest::READABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                stream.readable().await?;
            } else if err == WOLFSSL_ERROR_WANT_WRITE {
                let _: io::Result<()> = stream.try_io(Interest::WRITABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                stream.writable().await?;
            } else {
                let guard = ssl.lock().unwrap();
                unsafe { wolfSSL_free(guard.0) };
                return Err(io::Error::other(format!(
                    "wolfSSL_connect failed with error code: {}",
                    err
                )));
            }
        }

        Ok(Self { ssl, stream })
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }
}

impl AsyncRead for WolfTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            let unfilled = buf.initialize_unfilled();
            if unfilled.is_empty() {
                return Poll::Ready(Ok(()));
            }

            let (ret, err) = {
                let guard = this.ssl.lock().unwrap();
                let ret = unsafe {
                    wolfSSL_read(
                        guard.0,
                        unfilled.as_mut_ptr() as *mut std::ffi::c_void,
                        unfilled.len() as i32,
                    )
                };
                let err = if ret <= 0 {
                    unsafe { wolfSSL_get_error(guard.0, ret) }
                } else {
                    0
                };
                (ret, err)
            };

            if ret > 0 {
                buf.advance(ret as usize);
                return Poll::Ready(Ok(()));
            }

            if err == WOLFSSL_ERROR_WANT_READ {
                let _: io::Result<()> = this.stream.try_io(Interest::READABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                match this.stream.poll_read_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else if err == WOLFSSL_ERROR_WANT_WRITE {
                let _: io::Result<()> = this.stream.try_io(Interest::WRITABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                match this.stream.poll_write_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else if err == WOLFSSL_ERROR_ZERO_RETURN || ret == 0 {
                return Poll::Ready(Ok(()));
            } else {
                return Poll::Ready(Err(io::Error::other(format!(
                    "wolfSSL_read failed with error: {}",
                    err
                ))));
            }
        }
    }
}

impl AsyncWrite for WolfTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let (ret, err) = {
                let guard = this.ssl.lock().unwrap();
                let ret = unsafe {
                    wolfSSL_write(
                        guard.0,
                        buf.as_ptr() as *const std::ffi::c_void,
                        buf.len() as i32,
                    )
                };
                let err = if ret <= 0 {
                    unsafe { wolfSSL_get_error(guard.0, ret) }
                } else {
                    0
                };
                (ret, err)
            };

            if ret > 0 {
                return Poll::Ready(Ok(ret as usize));
            }

            if err == WOLFSSL_ERROR_WANT_WRITE {
                let _: io::Result<()> = this.stream.try_io(Interest::WRITABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                match this.stream.poll_write_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else if err == WOLFSSL_ERROR_WANT_READ {
                let _: io::Result<()> = this.stream.try_io(Interest::READABLE, || {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                });
                match this.stream.poll_read_ready(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                return Poll::Ready(Err(io::Error::other(format!(
                    "wolfSSL_write failed with error: {}",
                    err
                ))));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let guard = this.ssl.lock().unwrap();
        if !guard.0.is_null() {
            let _ = unsafe { wolfSSL_shutdown(guard.0) };
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

pub type TlsAcceptor = WolfTlsAcceptor;
pub type TlsConnector = WolfTlsConnector;
pub type TlsStream = WolfTlsStream;

/// Creates a wolfSSL TLS Acceptor for the MQTT server.
pub fn create_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
) -> Result<WolfTlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    ensure_wolfssl_initialized();

    if !Path::new(cert_path).exists() {
        return Err(format!("Server certificate file not found: {}", cert_path).into());
    }
    if !Path::new(key_path).exists() {
        return Err(format!("Server private key file not found: {}", key_path).into());
    }

    let method = unsafe { wolfSSLv23_server_method() };
    let raw_ctx = unsafe { wolfSSL_CTX_new(method) };
    if raw_ctx.is_null() {
        return Err("wolfSSL_CTX_new failed".into());
    }
    let ctx = Arc::new(WolfContext { raw: raw_ctx });

    let c_cert = CString::new(cert_path)?;
    if unsafe { wolfSSL_CTX_use_certificate_chain_file(ctx.as_ptr(), c_cert.as_ptr()) }
        != WOLFSSL_SUCCESS
    {
        return Err(format!("Failed to load server certificate chain from {}", cert_path).into());
    }

    let c_key = CString::new(key_path)?;
    if unsafe { wolfSSL_CTX_use_PrivateKey_file(ctx.as_ptr(), c_key.as_ptr(), SSL_FILETYPE_PEM) }
        != WOLFSSL_SUCCESS
    {
        return Err(format!("Failed to load server private key from {}", key_path).into());
    }

    if let Some(ca_path) = ca_cert_path {
        if !Path::new(ca_path).exists() {
            return Err(format!("CA certificate file not found: {}", ca_path).into());
        }
        let c_ca = CString::new(ca_path)?;
        if unsafe {
            wolfSSL_CTX_load_verify_locations(ctx.as_ptr(), c_ca.as_ptr(), std::ptr::null())
        } != WOLFSSL_SUCCESS
        {
            return Err(format!("Failed to load CA verify locations from {}", ca_path).into());
        }
        unsafe {
            wolfSSL_CTX_set_verify(
                ctx.as_ptr(),
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                None,
            );
        }
    } else {
        unsafe {
            wolfSSL_CTX_set_verify(ctx.as_ptr(), SSL_VERIFY_NONE, None);
        }
    }

    Ok(WolfTlsAcceptor { ctx })
}

/// Creates a wolfSSL TLS Connector for MQTT clients/benchmarks.
pub fn create_tls_connector(
    ca_cert_path: &str,
    client_cert_and_key: Option<(&str, &str)>,
) -> Result<WolfTlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    ensure_wolfssl_initialized();

    if !Path::new(ca_cert_path).exists() {
        return Err(format!("CA certificate file not found: {}", ca_cert_path).into());
    }

    let method = unsafe { wolfSSLv23_client_method() };
    let raw_ctx = unsafe { wolfSSL_CTX_new(method) };
    if raw_ctx.is_null() {
        return Err("wolfSSL_CTX_new failed".into());
    }
    let ctx = Arc::new(WolfContext { raw: raw_ctx });

    let c_ca = CString::new(ca_cert_path)?;
    if unsafe { wolfSSL_CTX_load_verify_locations(ctx.as_ptr(), c_ca.as_ptr(), std::ptr::null()) }
        != WOLFSSL_SUCCESS
    {
        return Err(format!("Failed to load CA verify locations from {}", ca_cert_path).into());
    }
    unsafe {
        wolfSSL_CTX_set_verify(ctx.as_ptr(), SSL_VERIFY_PEER, None);
    }

    if let Some((cert_path, key_path)) = client_cert_and_key {
        if !Path::new(cert_path).exists() {
            return Err(format!("Client certificate file not found: {}", cert_path).into());
        }
        if !Path::new(key_path).exists() {
            return Err(format!("Client private key file not found: {}", key_path).into());
        }

        let c_cert = CString::new(cert_path)?;
        if unsafe { wolfSSL_CTX_use_certificate_chain_file(ctx.as_ptr(), c_cert.as_ptr()) }
            != WOLFSSL_SUCCESS
        {
            return Err(
                format!("Failed to load client certificate chain from {}", cert_path).into(),
            );
        }

        let c_key = CString::new(key_path)?;
        if unsafe {
            wolfSSL_CTX_use_PrivateKey_file(ctx.as_ptr(), c_key.as_ptr(), SSL_FILETYPE_PEM)
        } != WOLFSSL_SUCCESS
        {
            return Err(format!("Failed to load client private key from {}", key_path).into());
        }
    }

    Ok(WolfTlsConnector { ctx })
}

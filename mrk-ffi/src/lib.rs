#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{CString, c_char},
    io,
    path::PathBuf,
    ptr, slice, str,
    sync::{Mutex as StdMutex, OnceLock},
    time::Duration,
};

use mrk_core::storage::DataPaths;
use mrk_sdk::{
    ClientOptions, ConnectionState, EncryptedStream, IncomingStream, MemberIdentity, RelayClient,
    RelayConnection, RelayError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};

pub const MRK_STATUS_OK: i32 = 0;
pub const MRK_STATUS_EOF: i32 = 1;
pub const MRK_STATUS_TIMEOUT: i32 = 2;
pub const MRK_ERROR_INVALID_ARGUMENT: i32 = 100;
pub const MRK_ERROR_INVALID_CONFIG: i32 = 101;
pub const MRK_ERROR_TRANSPORT: i32 = 102;
pub const MRK_ERROR_AUTHENTICATION: i32 = 103;
pub const MRK_ERROR_AUTHORIZATION: i32 = 104;
pub const MRK_ERROR_PEER_OFFLINE: i32 = 105;
pub const MRK_ERROR_PEER_REJECTED: i32 = 106;
pub const MRK_ERROR_HANDSHAKE_TIMEOUT: i32 = 107;
pub const MRK_ERROR_PROTOCOL: i32 = 108;
pub const MRK_ERROR_CRYPTO: i32 = 109;
pub const MRK_ERROR_CONNECTION_CLOSED: i32 = 110;
pub const MRK_ERROR_IO: i32 = 111;
pub const MRK_ERROR_INTERNAL: i32 = 112;

pub const MRK_CONNECTION_CONNECTED: i32 = 1;
pub const MRK_CONNECTION_CLOSED: i32 = 2;
pub const MRK_WAIT_FOREVER: u32 = u32::MAX;

const ABI_VERSION: u32 = 1;
const DEFAULT_STREAM_BUFFER_BYTES: usize = 256 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MrkBytesView {
    pub ptr: *const u8,
    pub len: usize,
}

impl MrkBytesView {
    const EMPTY: Self = Self {
        ptr: ptr::null(),
        len: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MrkIdentityOptions {
    pub struct_size: u32,
    pub data_dir: MrkBytesView,
    pub network: MrkBytesView,
    pub member: MrkBytesView,
    pub password: MrkBytesView,
    pub relay_endpoint: MrkBytesView,
    pub tls_ca_path: MrkBytesView,
    pub allow_insecure_local: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MrkConnectionOptions {
    pub struct_size: u32,
    pub endpoint: MrkBytesView,
    pub tls_ca_path: MrkBytesView,
    pub stream_buffer_bytes: usize,
    pub allow_insecure_local: u8,
}

pub struct MrkIdentity {
    inner: MemberIdentity,
}

pub struct MrkConnection {
    inner: RelayConnection,
}

pub struct MrkIncoming {
    inner: Option<IncomingStream>,
    peer_id: CString,
    authorization_id: CString,
    recovery: bool,
}

pub struct MrkStream {
    reader: StdMutex<ReadHalf<EncryptedStream>>,
    writer: StdMutex<WriteHalf<EncryptedStream>>,
    peer_id: CString,
    authorization_id: CString,
}

pub struct MrkError {
    code: i32,
    message: CString,
}

struct Failure {
    code: i32,
    message: String,
}

impl Failure {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(MRK_ERROR_INVALID_ARGUMENT, message)
    }

    fn io(error: io::Error) -> Self {
        Self::new(MRK_ERROR_IO, error.to_string())
    }

    fn relay(error: RelayError) -> Self {
        let code = match error {
            RelayError::InvalidConfig(_) => MRK_ERROR_INVALID_CONFIG,
            RelayError::Transport(_) => MRK_ERROR_TRANSPORT,
            RelayError::Authentication(_) => MRK_ERROR_AUTHENTICATION,
            RelayError::Authorization(_) => MRK_ERROR_AUTHORIZATION,
            RelayError::PeerOffline => MRK_ERROR_PEER_OFFLINE,
            RelayError::PeerRejected => MRK_ERROR_PEER_REJECTED,
            RelayError::HandshakeTimeout => MRK_ERROR_HANDSHAKE_TIMEOUT,
            RelayError::Protocol(_) => MRK_ERROR_PROTOCOL,
            RelayError::Crypto(_) => MRK_ERROR_CRYPTO,
            RelayError::ConnectionClosed => MRK_ERROR_CONNECTION_CLOSED,
        };
        Self::new(code, error.to_string())
    }
}

static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

fn runtime() -> Result<&'static tokio::runtime::Runtime, Failure> {
    match RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(message) => Err(Failure::new(MRK_ERROR_INTERNAL, message.clone())),
    }
}

fn c_string(value: impl AsRef<str>) -> CString {
    CString::new(value.as_ref().replace('\0', "�")).expect("replacement removes interior NUL bytes")
}

fn set_error(out_error: *mut *mut MrkError, failure: Failure) {
    if out_error.is_null() {
        return;
    }
    let error = Box::new(MrkError {
        code: failure.code,
        message: c_string(failure.message),
    });
    // SAFETY: The caller supplied a non-null output slot for an owned error pointer.
    unsafe {
        *out_error = Box::into_raw(error);
    }
}

fn ffi_call(
    out_error: *mut *mut MrkError,
    operation: impl FnOnce() -> Result<i32, Failure>,
) -> i32 {
    if !out_error.is_null() {
        // SAFETY: The caller supplied a non-null output slot. Clear it before execution.
        unsafe {
            *out_error = ptr::null_mut();
        }
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(Ok(status)) => status,
        Ok(Err(failure)) => {
            let code = failure.code;
            set_error(out_error, failure);
            code
        }
        Err(_) => {
            let failure = Failure::new(MRK_ERROR_INTERNAL, "Rust panic at the MRK C ABI boundary");
            set_error(out_error, failure);
            MRK_ERROR_INTERNAL
        }
    }
}

unsafe fn bytes<'a>(view: MrkBytesView, field: &str) -> Result<&'a [u8], Failure> {
    if view.len == 0 {
        return Ok(&[]);
    }
    if view.ptr.is_null() {
        return Err(Failure::invalid(format!(
            "{field} pointer is null but length is non-zero"
        )));
    }
    // SAFETY: The C caller guarantees that the view is readable for `len` bytes.
    Ok(unsafe { slice::from_raw_parts(view.ptr, view.len) })
}

unsafe fn text<'a>(view: MrkBytesView, field: &str, allow_empty: bool) -> Result<&'a str, Failure> {
    // SAFETY: Forwarding the caller's byte-view lifetime within the current FFI call.
    let value = str::from_utf8(unsafe { bytes(view, field)? })
        .map_err(|_| Failure::invalid(format!("{field} is not valid UTF-8")))?;
    if !allow_empty && value.is_empty() {
        return Err(Failure::invalid(format!("{field} must not be empty")));
    }
    Ok(value)
}

fn validate_size(actual: u32, expected: usize, name: &str) -> Result<(), Failure> {
    if usize::try_from(actual).unwrap_or(0) < expected {
        return Err(Failure::invalid(format!(
            "{name}.struct_size is smaller than this ABI version requires"
        )));
    }
    Ok(())
}

fn incoming_handle(incoming: IncomingStream) -> MrkIncoming {
    MrkIncoming {
        peer_id: c_string(incoming.peer_id()),
        authorization_id: c_string(incoming.authorization_id()),
        recovery: incoming.is_recovery(),
        inner: Some(incoming),
    }
}

fn stream_handle(stream: EncryptedStream) -> MrkStream {
    let peer_id = c_string(stream.peer_id());
    let authorization_id = c_string(stream.authorization_id());
    let (reader, writer) = split(stream);
    MrkStream {
        reader: StdMutex::new(reader),
        writer: StdMutex::new(writer),
        peer_id,
        authorization_id,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mrk_sdk_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn mrk_sdk_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_identity_options_init(options: *mut MrkIdentityOptions) {
    if options.is_null() {
        return;
    }
    // SAFETY: The caller supplied writable storage for the options structure.
    unsafe {
        *options = MrkIdentityOptions {
            struct_size: size_of::<MrkIdentityOptions>() as u32,
            data_dir: MrkBytesView::EMPTY,
            network: MrkBytesView::EMPTY,
            member: MrkBytesView::EMPTY,
            password: MrkBytesView::EMPTY,
            relay_endpoint: MrkBytesView::EMPTY,
            tls_ca_path: MrkBytesView::EMPTY,
            allow_insecure_local: 0,
        };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_options_init(options: *mut MrkConnectionOptions) {
    if options.is_null() {
        return;
    }
    // SAFETY: The caller supplied writable storage for the options structure.
    unsafe {
        *options = MrkConnectionOptions {
            struct_size: size_of::<MrkConnectionOptions>() as u32,
            endpoint: MrkBytesView::EMPTY,
            tls_ca_path: MrkBytesView::EMPTY,
            stream_buffer_bytes: DEFAULT_STREAM_BUFFER_BYTES,
            allow_insecure_local: 0,
        };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_identity_from_relay(
    options: *const MrkIdentityOptions,
    out_identity: *mut *mut MrkIdentity,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if options.is_null() || out_identity.is_null() {
            return Err(Failure::invalid(
                "options and out_identity must not be null",
            ));
        }
        // SAFETY: Validated non-null pointers owned by the caller for this call.
        let options = unsafe { *options };
        // SAFETY: Validated writable output slot.
        unsafe { *out_identity = ptr::null_mut() };
        validate_size(
            options.struct_size,
            size_of::<MrkIdentityOptions>(),
            "identity options",
        )?;
        // SAFETY: Input views remain valid for the duration of this blocking call.
        let data_dir = unsafe { text(options.data_dir, "data_dir", true)? };
        // SAFETY: Same as above.
        let network = unsafe { text(options.network, "network", false)? };
        // SAFETY: Same as above.
        let member = unsafe { text(options.member, "member", false)? };
        // SAFETY: Same as above.
        let password = unsafe { text(options.password, "password", false)? };
        // SAFETY: Same as above.
        let endpoint = unsafe { text(options.relay_endpoint, "relay_endpoint", false)? };
        // SAFETY: Same as above.
        let tls_ca = unsafe { text(options.tls_ca_path, "tls_ca_path", true)? };
        let paths = DataPaths::new(if data_dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(data_dir))
        })
        .map_err(|error| Failure::new(MRK_ERROR_INVALID_CONFIG, error.to_string()))?;
        let tls_path = (!tls_ca.is_empty()).then(|| PathBuf::from(tls_ca));
        let identity = runtime()?
            .block_on(MemberIdentity::from_relay(
                &paths,
                network,
                member,
                password,
                endpoint,
                options.allow_insecure_local != 0,
                tls_path.as_deref(),
            ))
            .map_err(Failure::relay)?;
        // SAFETY: The caller owns the returned opaque handle and frees it with mrk_identity_free.
        unsafe {
            *out_identity = Box::into_raw(Box::new(MrkIdentity { inner: identity }));
        }
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_identity_free(identity: *mut MrkIdentity) {
    if !identity.is_null() {
        // SAFETY: Pointer was returned by mrk_identity_from_relay and is freed once.
        unsafe { drop(Box::from_raw(identity)) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_connect(
    options: *const MrkConnectionOptions,
    identity: *const MrkIdentity,
    out_connection: *mut *mut MrkConnection,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if options.is_null() || identity.is_null() || out_connection.is_null() {
            return Err(Failure::invalid(
                "options, identity, and out_connection must not be null",
            ));
        }
        // SAFETY: Validated pointers remain alive for this blocking call.
        let options = unsafe { *options };
        // SAFETY: Validated identity handle.
        let identity = unsafe { &*identity };
        // SAFETY: Validated writable output slot.
        unsafe { *out_connection = ptr::null_mut() };
        validate_size(
            options.struct_size,
            size_of::<MrkConnectionOptions>(),
            "connection options",
        )?;
        if options.stream_buffer_bytes == 0 {
            return Err(Failure::invalid(
                "stream_buffer_bytes must be greater than zero",
            ));
        }
        // SAFETY: Input views remain valid for this blocking call.
        let endpoint = unsafe { text(options.endpoint, "endpoint", false)? };
        // SAFETY: Same as above.
        let tls_ca = unsafe { text(options.tls_ca_path, "tls_ca_path", true)? };
        let mut client_options = ClientOptions::new(endpoint, identity.inner.clone())
            .allow_insecure_local(options.allow_insecure_local != 0)
            .stream_buffer_bytes(options.stream_buffer_bytes);
        if !tls_ca.is_empty() {
            client_options = client_options.tls_ca(tls_ca);
        }
        let connection = runtime()?
            .block_on(RelayClient::connect(client_options))
            .map_err(Failure::relay)?;
        // SAFETY: The caller owns the returned opaque connection handle.
        unsafe {
            *out_connection = Box::into_raw(Box::new(MrkConnection { inner: connection }));
        }
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_state(
    connection: *const MrkConnection,
    out_state: *mut i32,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() || out_state.is_null() {
            return Err(Failure::invalid(
                "connection and out_state must not be null",
            ));
        }
        // SAFETY: Validated live connection handle and writable output slot.
        let connection = unsafe { &*connection };
        let state = *connection.inner.subscribe_state().borrow();
        unsafe {
            *out_state = match state {
                ConnectionState::Connected => MRK_CONNECTION_CONNECTED,
                ConnectionState::Closed => MRK_CONNECTION_CLOSED,
            };
        }
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_open_auto(
    connection: *mut MrkConnection,
    peer_id: MrkBytesView,
    out_stream: *mut *mut MrkStream,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() || out_stream.is_null() {
            return Err(Failure::invalid(
                "connection and out_stream must not be null",
            ));
        }
        // SAFETY: The input view and handle remain valid for this blocking call.
        let peer_id = unsafe { text(peer_id, "peer_id", false)? };
        // SAFETY: Validated writable output slot.
        unsafe { *out_stream = ptr::null_mut() };
        // SAFETY: Validated live connection handle.
        let connection = unsafe { &*connection };
        let stream = runtime()?
            .block_on(connection.inner.open_auto(peer_id))
            .map_err(Failure::relay)?;
        // SAFETY: The caller owns the returned opaque stream handle.
        unsafe { *out_stream = Box::into_raw(Box::new(stream_handle(stream))) };
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_open_existing(
    connection: *mut MrkConnection,
    peer_id: MrkBytesView,
    authorization_id: MrkBytesView,
    out_stream: *mut *mut MrkStream,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() || out_stream.is_null() {
            return Err(Failure::invalid(
                "connection and out_stream must not be null",
            ));
        }
        // SAFETY: Views remain valid for this blocking call.
        let peer_id = unsafe { text(peer_id, "peer_id", false)? };
        // SAFETY: Same as above.
        let authorization_id = unsafe { text(authorization_id, "authorization_id", false)? };
        // SAFETY: Validated pointers.
        unsafe { *out_stream = ptr::null_mut() };
        let connection = unsafe { &*connection };
        let stream = runtime()?
            .block_on(connection.inner.open_existing(peer_id, authorization_id))
            .map_err(Failure::relay)?;
        // SAFETY: The caller owns the returned opaque stream handle.
        unsafe { *out_stream = Box::into_raw(Box::new(stream_handle(stream))) };
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_recover_existing(
    connection: *mut MrkConnection,
    peer_id: MrkBytesView,
    authorization_id: MrkBytesView,
    max_auto_recovery_bytes: u64,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() {
            return Err(Failure::invalid("connection must not be null"));
        }
        // SAFETY: Views remain valid for this blocking call.
        let peer_id = unsafe { text(peer_id, "peer_id", false)? };
        // SAFETY: Same as above.
        let authorization_id = unsafe { text(authorization_id, "authorization_id", false)? };
        // SAFETY: Validated live connection handle.
        let connection = unsafe { &*connection };
        runtime()?
            .block_on(connection.inner.recover_existing(
                peer_id,
                authorization_id,
                max_auto_recovery_bytes,
            ))
            .map_err(Failure::relay)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_accept(
    connection: *mut MrkConnection,
    timeout_ms: u32,
    out_incoming: *mut *mut MrkIncoming,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() || out_incoming.is_null() {
            return Err(Failure::invalid(
                "connection and out_incoming must not be null",
            ));
        }
        // SAFETY: Validated writable output slot and live handle.
        unsafe { *out_incoming = ptr::null_mut() };
        let connection = unsafe { &*connection };
        let incoming = if timeout_ms == MRK_WAIT_FOREVER {
            runtime()?
                .block_on(connection.inner.accept())
                .map_err(Failure::relay)?
        } else {
            match runtime()?.block_on(tokio::time::timeout(
                Duration::from_millis(u64::from(timeout_ms)),
                connection.inner.accept(),
            )) {
                Ok(result) => result.map_err(Failure::relay)?,
                Err(_) => return Ok(MRK_STATUS_TIMEOUT),
            }
        };
        // SAFETY: The caller owns the returned opaque incoming handle.
        unsafe { *out_incoming = Box::into_raw(Box::new(incoming_handle(incoming))) };
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_close(
    connection: *mut MrkConnection,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if connection.is_null() {
            return Err(Failure::invalid("connection must not be null"));
        }
        // SAFETY: Validated live connection handle.
        let connection = unsafe { &*connection };
        runtime()?
            .block_on(connection.inner.close())
            .map_err(Failure::relay)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_connection_free(connection: *mut MrkConnection) {
    if !connection.is_null() {
        // SAFETY: Pointer was returned by mrk_connection_connect and is freed once.
        unsafe { drop(Box::from_raw(connection)) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_peer_id(incoming: *const MrkIncoming) -> *const c_char {
    if incoming.is_null() {
        return ptr::null();
    }
    // SAFETY: Validated live incoming handle; CString lives with the handle.
    unsafe { (*incoming).peer_id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_authorization_id(
    incoming: *const MrkIncoming,
) -> *const c_char {
    if incoming.is_null() {
        return ptr::null();
    }
    // SAFETY: Validated live incoming handle; CString lives with the handle.
    unsafe { (*incoming).authorization_id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_is_recovery(incoming: *const MrkIncoming) -> u8 {
    if incoming.is_null() {
        return 0;
    }
    // SAFETY: Validated live incoming handle.
    u8::from(unsafe { (*incoming).recovery })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_accept(
    incoming: *mut MrkIncoming,
    out_stream: *mut *mut MrkStream,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if incoming.is_null() || out_stream.is_null() {
            return Err(Failure::invalid("incoming and out_stream must not be null"));
        }
        // SAFETY: Validated writable output slot and exclusive incoming handle.
        unsafe { *out_stream = ptr::null_mut() };
        let incoming = unsafe { &mut *incoming };
        let pending = incoming
            .inner
            .take()
            .ok_or_else(|| Failure::invalid("incoming request was already consumed"))?;
        let stream = runtime()?
            .block_on(pending.accept())
            .map_err(Failure::relay)?;
        // SAFETY: The caller owns the returned opaque stream handle.
        unsafe { *out_stream = Box::into_raw(Box::new(stream_handle(stream))) };
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_recover(
    incoming: *mut MrkIncoming,
    max_auto_recovery_bytes: u64,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if incoming.is_null() {
            return Err(Failure::invalid("incoming must not be null"));
        }
        // SAFETY: Validated exclusive incoming handle.
        let incoming = unsafe { &mut *incoming };
        let pending = incoming
            .inner
            .take()
            .ok_or_else(|| Failure::invalid("incoming request was already consumed"))?;
        runtime()?
            .block_on(pending.recover(max_auto_recovery_bytes))
            .map_err(Failure::relay)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_reject(
    incoming: *mut MrkIncoming,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if incoming.is_null() {
            return Err(Failure::invalid("incoming must not be null"));
        }
        // SAFETY: Validated exclusive incoming handle.
        let incoming = unsafe { &mut *incoming };
        let pending = incoming
            .inner
            .take()
            .ok_or_else(|| Failure::invalid("incoming request was already consumed"))?;
        runtime()?
            .block_on(pending.reject())
            .map_err(Failure::relay)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_incoming_free(incoming: *mut MrkIncoming) {
    if !incoming.is_null() {
        // SAFETY: Pointer was returned by mrk_connection_accept and is freed once.
        unsafe { drop(Box::from_raw(incoming)) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_peer_id(stream: *const MrkStream) -> *const c_char {
    if stream.is_null() {
        return ptr::null();
    }
    // SAFETY: Validated live stream handle; CString lives with the handle.
    unsafe { (*stream).peer_id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_authorization_id(stream: *const MrkStream) -> *const c_char {
    if stream.is_null() {
        return ptr::null();
    }
    // SAFETY: Validated live stream handle; CString lives with the handle.
    unsafe { (*stream).authorization_id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_read(
    stream: *mut MrkStream,
    buffer: *mut u8,
    capacity: usize,
    out_read: *mut usize,
    timeout_ms: u32,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if stream.is_null() || out_read.is_null() || (capacity > 0 && buffer.is_null()) {
            return Err(Failure::invalid(
                "stream, out_read, and non-empty buffer must not be null",
            ));
        }
        // SAFETY: Validated writable output slot.
        unsafe { *out_read = 0 };
        if capacity == 0 {
            return Ok(MRK_STATUS_OK);
        }
        // SAFETY: Caller guarantees writable storage for capacity bytes.
        let buffer = unsafe { slice::from_raw_parts_mut(buffer, capacity) };
        // SAFETY: Validated live stream handle.
        let stream = unsafe { &*stream };
        let mut reader = stream
            .reader
            .lock()
            .map_err(|_| Failure::new(MRK_ERROR_INTERNAL, "stream reader lock was poisoned"))?;
        let count = if timeout_ms == MRK_WAIT_FOREVER {
            runtime()?
                .block_on(reader.read(buffer))
                .map_err(Failure::io)?
        } else {
            match runtime()?.block_on(tokio::time::timeout(
                Duration::from_millis(u64::from(timeout_ms)),
                reader.read(buffer),
            )) {
                Ok(result) => result.map_err(Failure::io)?,
                Err(_) => return Ok(MRK_STATUS_TIMEOUT),
            }
        };
        // SAFETY: Validated writable output slot.
        unsafe { *out_read = count };
        Ok(if count == 0 {
            MRK_STATUS_EOF
        } else {
            MRK_STATUS_OK
        })
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_write(
    stream: *mut MrkStream,
    data: *const u8,
    length: usize,
    out_written: *mut usize,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if stream.is_null() || out_written.is_null() || (length > 0 && data.is_null()) {
            return Err(Failure::invalid(
                "stream, out_written, and non-empty data must not be null",
            ));
        }
        // SAFETY: Validated writable output slot.
        unsafe { *out_written = 0 };
        if length == 0 {
            return Ok(MRK_STATUS_OK);
        }
        // SAFETY: Caller guarantees readable storage for length bytes.
        let data = unsafe { slice::from_raw_parts(data, length) };
        // SAFETY: Validated live stream handle.
        let stream = unsafe { &*stream };
        let mut writer = stream
            .writer
            .lock()
            .map_err(|_| Failure::new(MRK_ERROR_INTERNAL, "stream writer lock was poisoned"))?;
        let count = runtime()?
            .block_on(writer.write(data))
            .map_err(Failure::io)?;
        // SAFETY: Validated writable output slot.
        unsafe { *out_written = count };
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_flush(
    stream: *mut MrkStream,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if stream.is_null() {
            return Err(Failure::invalid("stream must not be null"));
        }
        // SAFETY: Validated live stream handle.
        let stream = unsafe { &*stream };
        let mut writer = stream
            .writer
            .lock()
            .map_err(|_| Failure::new(MRK_ERROR_INTERNAL, "stream writer lock was poisoned"))?;
        runtime()?.block_on(writer.flush()).map_err(Failure::io)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_shutdown_write(
    stream: *mut MrkStream,
    out_error: *mut *mut MrkError,
) -> i32 {
    ffi_call(out_error, || {
        if stream.is_null() {
            return Err(Failure::invalid("stream must not be null"));
        }
        // SAFETY: Validated live stream handle.
        let stream = unsafe { &*stream };
        let mut writer = stream
            .writer
            .lock()
            .map_err(|_| Failure::new(MRK_ERROR_INTERNAL, "stream writer lock was poisoned"))?;
        runtime()?
            .block_on(writer.shutdown())
            .map_err(Failure::io)?;
        Ok(MRK_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_stream_free(stream: *mut MrkStream) {
    if !stream.is_null() {
        // SAFETY: Pointer was returned by a stream-opening function and is freed once.
        unsafe { drop(Box::from_raw(stream)) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_error_code(error: *const MrkError) -> i32 {
    if error.is_null() {
        return MRK_ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: Validated live error handle.
    unsafe { (*error).code }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_error_message(error: *const MrkError) -> *const c_char {
    if error.is_null() {
        return ptr::null();
    }
    // SAFETY: Validated live error handle; CString lives with the handle.
    unsafe { (*error).message.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mrk_error_free(error: *mut MrkError) {
    if !error.is_null() {
        // SAFETY: Pointer was returned through an out_error slot and is freed once.
        unsafe { drop(Box::from_raw(error)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_initializers_publish_current_sizes_and_defaults() {
        let mut identity = std::mem::MaybeUninit::<MrkIdentityOptions>::uninit();
        let mut connection = std::mem::MaybeUninit::<MrkConnectionOptions>::uninit();
        // SAFETY: Both pointers refer to writable MaybeUninit storage.
        unsafe {
            mrk_identity_options_init(identity.as_mut_ptr());
            mrk_connection_options_init(connection.as_mut_ptr());
            let identity = identity.assume_init();
            let connection = connection.assume_init();
            assert_eq!(
                identity.struct_size as usize,
                size_of::<MrkIdentityOptions>()
            );
            assert_eq!(
                connection.struct_size as usize,
                size_of::<MrkConnectionOptions>()
            );
            assert_eq!(connection.stream_buffer_bytes, DEFAULT_STREAM_BUFFER_BYTES);
        }
    }

    #[test]
    fn invalid_arguments_return_owned_error() {
        let mut error = ptr::null_mut();
        // SAFETY: Null required arguments intentionally exercise validation.
        let status = unsafe { mrk_identity_from_relay(ptr::null(), ptr::null_mut(), &mut error) };
        assert_eq!(status, MRK_ERROR_INVALID_ARGUMENT);
        assert!(!error.is_null());
        // SAFETY: Error came from the FFI function and is freed exactly once.
        unsafe {
            assert_eq!(mrk_error_code(error), MRK_ERROR_INVALID_ARGUMENT);
            assert!(!mrk_error_message(error).is_null());
            mrk_error_free(error);
        }
    }
}

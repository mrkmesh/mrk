#ifndef MRK_SDK_H
#define MRK_SDK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t mrk_status_t;

enum {
    MRK_STATUS_OK = 0,
    MRK_STATUS_EOF = 1,
    MRK_STATUS_TIMEOUT = 2,

    MRK_ERROR_INVALID_ARGUMENT = 100,
    MRK_ERROR_INVALID_CONFIG = 101,
    MRK_ERROR_TRANSPORT = 102,
    MRK_ERROR_AUTHENTICATION = 103,
    MRK_ERROR_AUTHORIZATION = 104,
    MRK_ERROR_PEER_OFFLINE = 105,
    MRK_ERROR_PEER_REJECTED = 106,
    MRK_ERROR_HANDSHAKE_TIMEOUT = 107,
    MRK_ERROR_PROTOCOL = 108,
    MRK_ERROR_CRYPTO = 109,
    MRK_ERROR_CONNECTION_CLOSED = 110,
    MRK_ERROR_IO = 111,
    MRK_ERROR_INTERNAL = 112,
};

enum {
    MRK_CONNECTION_CONNECTED = 1,
    MRK_CONNECTION_CLOSED = 2,
};

#define MRK_WAIT_FOREVER UINT32_MAX

typedef struct mrk_identity mrk_identity_t;
typedef struct mrk_connection mrk_connection_t;
typedef struct mrk_incoming mrk_incoming_t;
typedef struct mrk_stream mrk_stream_t;
typedef struct mrk_error mrk_error_t;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} mrk_bytes_view_t;

typedef struct {
    uint32_t struct_size;
    mrk_bytes_view_t data_dir;
    mrk_bytes_view_t network;
    mrk_bytes_view_t member;
    mrk_bytes_view_t password;
    mrk_bytes_view_t relay_endpoint;
    mrk_bytes_view_t tls_ca_path;
    uint8_t allow_insecure_local;
} mrk_identity_options_t;

typedef struct {
    uint32_t struct_size;
    mrk_bytes_view_t endpoint;
    mrk_bytes_view_t tls_ca_path;
    size_t stream_buffer_bytes;
    uint8_t allow_insecure_local;
} mrk_connection_options_t;

static inline mrk_bytes_view_t mrk_string_view(const char *value) {
    mrk_bytes_view_t view;
    view.ptr = (const uint8_t *)value;
    view.len = value == NULL ? 0 : strlen(value);
    return view;
}

uint32_t mrk_sdk_abi_version(void);
const char *mrk_sdk_version(void);

void mrk_identity_options_init(mrk_identity_options_t *options);
void mrk_connection_options_init(mrk_connection_options_t *options);

mrk_status_t mrk_identity_from_relay(
    const mrk_identity_options_t *options,
    mrk_identity_t **out_identity,
    mrk_error_t **out_error
);
void mrk_identity_free(mrk_identity_t *identity);

mrk_status_t mrk_connection_connect(
    const mrk_connection_options_t *options,
    const mrk_identity_t *identity,
    mrk_connection_t **out_connection,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_state(
    const mrk_connection_t *connection,
    int32_t *out_state,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_open_auto(
    mrk_connection_t *connection,
    mrk_bytes_view_t peer_id,
    mrk_stream_t **out_stream,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_open_existing(
    mrk_connection_t *connection,
    mrk_bytes_view_t peer_id,
    mrk_bytes_view_t authorization_id,
    mrk_stream_t **out_stream,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_recover_existing(
    mrk_connection_t *connection,
    mrk_bytes_view_t peer_id,
    mrk_bytes_view_t authorization_id,
    uint64_t max_auto_recovery_bytes,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_accept(
    mrk_connection_t *connection,
    uint32_t timeout_ms,
    mrk_incoming_t **out_incoming,
    mrk_error_t **out_error
);
mrk_status_t mrk_connection_close(
    mrk_connection_t *connection,
    mrk_error_t **out_error
);
void mrk_connection_free(mrk_connection_t *connection);

const char *mrk_incoming_peer_id(const mrk_incoming_t *incoming);
const char *mrk_incoming_authorization_id(const mrk_incoming_t *incoming);
uint8_t mrk_incoming_is_recovery(const mrk_incoming_t *incoming);
mrk_status_t mrk_incoming_accept(
    mrk_incoming_t *incoming,
    mrk_stream_t **out_stream,
    mrk_error_t **out_error
);
mrk_status_t mrk_incoming_recover(
    mrk_incoming_t *incoming,
    uint64_t max_auto_recovery_bytes,
    mrk_error_t **out_error
);
mrk_status_t mrk_incoming_reject(
    mrk_incoming_t *incoming,
    mrk_error_t **out_error
);
void mrk_incoming_free(mrk_incoming_t *incoming);

const char *mrk_stream_peer_id(const mrk_stream_t *stream);
const char *mrk_stream_authorization_id(const mrk_stream_t *stream);
mrk_status_t mrk_stream_read(
    mrk_stream_t *stream,
    uint8_t *buffer,
    size_t capacity,
    size_t *out_read,
    uint32_t timeout_ms,
    mrk_error_t **out_error
);
mrk_status_t mrk_stream_write(
    mrk_stream_t *stream,
    const uint8_t *data,
    size_t length,
    size_t *out_written,
    mrk_error_t **out_error
);
mrk_status_t mrk_stream_flush(
    mrk_stream_t *stream,
    mrk_error_t **out_error
);
mrk_status_t mrk_stream_shutdown_write(
    mrk_stream_t *stream,
    mrk_error_t **out_error
);
void mrk_stream_free(mrk_stream_t *stream);

mrk_status_t mrk_error_code(const mrk_error_t *error);
const char *mrk_error_message(const mrk_error_t *error);
void mrk_error_free(mrk_error_t *error);

/*
 * Ownership and concurrency rules:
 * - Every handle returned through an out parameter must be released with its
 *   matching *_free function. All *_free functions accept NULL.
 * - Input views are borrowed only for the duration of the call.
 * - Returned const char pointers are borrowed from their handle and become
 *   invalid when that handle is freed.
 * - Do not free a handle while another thread is using it.
 * - A stream supports one concurrent reader and one concurrent writer. Calls
 *   in the same direction must be serialized by the caller.
 * - mrk_stream_shutdown_write performs the authenticated FIN/receipt exchange;
 *   call it before mrk_stream_free for graceful settlement.
 * - Network functions are blocking. Invoke them on application worker threads.
 */

#ifdef __cplusplus
}
#endif

#endif

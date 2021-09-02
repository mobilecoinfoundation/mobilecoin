// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef ENCODINGS_H_
#define ENCODINGS_H_

#include "common.h"

/* ==================== Encodings ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== PrintableWrapper ==== */

/// # Preconditions
///
/// * `printable_wrapper_proto_bytes` - must be a valid binary-serialized `printable.PrintableWrapper`
///     Protobuf.
char* MC_NULLABLE mc_printable_wrapper_b58_encode(
  const McBuffer* MC_NONNULL printable_wrapper_proto_bytes
)
MC_ATTRIBUTE_NONNULL(1);

/// # Preconditions
///
/// * `b58_encoded_string` - must be a nul-terminated C string containing valid UTF-8.
/// * `out_printable_wrapper_proto_bytes` - must be null or else length must be >=
///     `wrapper_bytes.len`.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
ssize_t mc_printable_wrapper_b58_decode(
  const char* MC_NONNULL b58_encoded_string,
  McMutableBuffer* MC_NULLABLE out_printable_wrapper_proto_bytes,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* !ENCODINGS_H_ */

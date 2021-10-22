// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef COMMON_H_
#define COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

// Compatibility with non-clang compilers.
#ifndef __has_attribute
#  define __has_attribute(x) 0
#endif

#if __has_attribute(nonnull)
#  define MC_ATTRIBUTE_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#  define MC_ATTRIBUTE_NONNULL(...)
#endif

#ifdef __llvm__
#  define MC_NONNULL _Nonnull
#  define MC_NULLABLE _Nullable
#else
#  define MC_NONNULL
#  define MC_NULLABLE
#endif

#if __has_attribute(enum_extensibility)
#  define MC_ATTRIBUTE_ENUM_CLOSED __attribute__((enum_extensibility(closed)))
#else
#  define MC_ATTRIBUTE_ENUM_CLOSED
#endif

/* ==================== Common ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Error Codes ==== */

typedef enum MC_ATTRIBUTE_ENUM_CLOSED {
  McErrorCodeUnknown = -1,
  McErrorCodePanic = -2,

  McErrorCodeInvalidInput = 100,
  McErrorCodeInvalidOutput = 101,

  McErrorCodeAttestationVerificationFailed = 200,

  McErrorCodeAead = 300,
  McErrorCodeCipher = 301,
  McErrorCodeUnsupportedCryptoBoxVersion = 302,

  McErrorCodeTransactionCrypto = 400,

  McErrorCodeFogPubkey = 500,
} McErrorCode;

/* ==== McError ==== */

typedef struct {
  int error_code;
  const char* MC_NONNULL error_description;
} McError;

void mc_error_free(McError* MC_NULLABLE error);

/* ==== McString ==== */

void mc_string_free(char* MC_NULLABLE string);

/* ==== McBuffer ==== */

typedef struct {
  const uint8_t* MC_NONNULL buffer;
  size_t len;
} McBuffer;

typedef struct {
  uint8_t* MC_NONNULL buffer;
  size_t len;
} McMutableBuffer;

/* ==== McData ==== */

typedef struct _McData McData;

void mc_data_free(McData* MC_NULLABLE data);

/// # Preconditions
///
/// * `out_bytes` - must be null or else length must be >= `data.len`.
ssize_t mc_data_get_bytes(
  const McData* MC_NONNULL data,
  McMutableBuffer* MC_NULLABLE out_bytes
)
MC_ATTRIBUTE_NONNULL(1);

/* ==== McRngCallback ==== */

typedef struct {
  uint64_t (* MC_NONNULL rng)(void* MC_NULLABLE);
  void* MC_NULLABLE context;
} McRngCallback;

#ifdef __cplusplus
}
#endif

#endif /* !COMMON_H_ */

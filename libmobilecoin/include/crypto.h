// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "common.h"

/* ==================== Crypto ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Ristretto ==== */

bool mc_ristretto_private_validate(
  const McBuffer* MC_NONNULL ristretto_private,
  bool* MC_NONNULL out_valid
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `ristretto_private` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_ristretto_public` - length must be >= 32.
bool mc_ristretto_public_from_ristretto_private(
  const McBuffer* MC_NONNULL ristretto_private,
  McMutableBuffer* MC_NONNULL out_ristretto_public
)
MC_ATTRIBUTE_NONNULL(1, 2);

bool mc_ristretto_public_validate(
  const McBuffer* MC_NONNULL ristretto_public,
  bool* MC_NONNULL out_valid
)
MC_ATTRIBUTE_NONNULL(1, 2);

/* ==== VersionedCryptoBox ==== */

/// # Preconditions
///
/// * `public_key` - must be a valid 32-byte compressed Ristretto point.
/// * `out_ciphertext` - must be null or else length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
ssize_t mc_versioned_crypto_box_encrypt(
  const McBuffer* MC_NONNULL public_key,
  const McBuffer* MC_NONNULL plaintext,
  McRngCallback* MC_NULLABLE rng_callback,
  McMutableBuffer* MC_NULLABLE out_ciphertext,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_plaintext` - length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
ssize_t mc_versioned_crypto_box_decrypt(
  const McBuffer* MC_NONNULL private_key,
  const McBuffer* MC_NONNULL ciphertext,
  McMutableBuffer* MC_NONNULL out_plaintext,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

#ifdef __cplusplus
}
#endif

#endif /* !CRYPTO_H_ */

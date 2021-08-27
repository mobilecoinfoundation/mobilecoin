// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef ATTEST_H_
#define ATTEST_H_

#include "common.h"

/* ==================== Attestation ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Types ==== */

/// A `VerifyIasReportData` implementation that will check if the enclave in
/// question has the given MrEnclave, and has no other IAS report status issues.
typedef struct _McMrEnclaveVerifier McMrEnclaveVerifier;

/// A `VerifyIasReportData` implementation that will check if the enclave in
/// question has the given MrSigner value, and has no other IAS report status
/// issues.
typedef struct _McMrSignerVerifier McMrSignerVerifier;

/// A builder structure used to construct a report verifier based on the
/// criteria specified.
typedef struct _McVerifier McVerifier;

typedef struct _McAttestAke McAttestAke;

/* ==== McMrEnclaveVerifier ==== */

/// Create a new status verifier that will check for the existence of the
/// given MrEnclave.
///
/// # Preconditions
///
/// * `mr_enclave` - must be 32 bytes in length.
McMrEnclaveVerifier* MC_NULLABLE mc_mr_enclave_verifier_create(
  const McBuffer* MC_NONNULL mr_enclave
)
MC_ATTRIBUTE_NONNULL(1);

void mc_mr_enclave_verifier_free(
  McMrEnclaveVerifier* MC_NULLABLE mr_enclave_verifier
);

/// Assume an enclave with the specified measurement does not need
/// BIOS configuration changes to address the provided advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
bool mc_mr_enclave_verifier_allow_config_advisory(
  McMrEnclaveVerifier* MC_NONNULL mr_enclave_verifier,
  const char* MC_NONNULL advisory_id
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// Assume the given MrEnclave value has the appropriate software/build-time
/// hardening for the given advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
bool mc_mr_enclave_verifier_allow_hardening_advisory(
  McMrEnclaveVerifier* MC_NONNULL mr_enclave_verifier,
  const char* MC_NONNULL advisory_id
)
MC_ATTRIBUTE_NONNULL(1, 2);

/* ==== McMrSignerVerifier ==== */

/// Create a new status verifier that will check for the existence of the
/// given MrSigner.
///
/// # Preconditions
///
/// * `mr_signer` - must be 32 bytes in length.
McMrSignerVerifier* MC_NULLABLE mc_mr_signer_verifier_create(
  const McBuffer* MC_NONNULL mr_signer,
  uint16_t expected_product_id,
  uint16_t minimum_security_version
)
MC_ATTRIBUTE_NONNULL(1);

void mc_mr_signer_verifier_free(
  McMrSignerVerifier* MC_NULLABLE mr_signer_verifier
);

/// Assume an enclave with the specified measurement does not need
/// BIOS configuration changes to address the provided advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
bool mc_mr_signer_verifier_allow_config_advisory(
  McMrSignerVerifier* MC_NONNULL mr_signer_verifier,
  const char* MC_NONNULL advisory_id
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// Assume an enclave with the specified measurement has the appropriate
/// software/build-time hardening for the given advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
bool mc_mr_signer_verifier_allow_hardening_advisory(
  McMrSignerVerifier* MC_NONNULL mr_signer_verifier,
  const char* MC_NONNULL advisory_id
)
MC_ATTRIBUTE_NONNULL(1, 2);

/* ==== McVerifier ==== */

/// Construct a new builder using the baked-in IAS root certificates and debug
/// settings.
McVerifier* MC_NULLABLE mc_verifier_create();

void mc_verifier_free(
  McVerifier* MC_NULLABLE verifier
);

/// Verify the given MrEnclave-based status verifier succeeds
bool mc_verifier_add_mr_enclave(
  McVerifier* MC_NONNULL verifier,
  const McMrEnclaveVerifier* MC_NONNULL mr_enclave_verifier
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// Verify the given MrSigner-based status verifier succeeds
bool mc_verifier_add_mr_signer(
  McVerifier* MC_NONNULL verifier,
  const McMrSignerVerifier* MC_NONNULL mr_signer_verifier
)
MC_ATTRIBUTE_NONNULL(1, 2);

/* ==== McAttestAke ==== */

McAttestAke* MC_NULLABLE mc_attest_ake_create();

void mc_attest_ake_free(
  McAttestAke* MC_NULLABLE attest_ake
);

bool mc_attest_ake_is_attested(
  const McAttestAke* MC_NONNULL attest_ake,
  bool* MC_NONNULL out_attested
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_binding` - must be null or else length must be >= `binding.len`.
ssize_t mc_attest_ake_get_binding(
  const McAttestAke* MC_NONNULL attest_ake,
  McMutableBuffer* MC_NULLABLE out_binding
)
MC_ATTRIBUTE_NONNULL(1);

/* ==== Auth ==== */

/// # Preconditions
///
/// * `responder_id` - must be a nul-terminated C string containing a valid responder ID.
/// * `out_auth_request` - must be null or else length must be >= auth_request_output.len.
ssize_t mc_attest_ake_get_auth_request(
  McAttestAke* MC_NONNULL attest_ake,
  const char* MC_NONNULL responder_id,
  McRngCallback* MC_NULLABLE rng_callback,
  McMutableBuffer* MC_NULLABLE out_auth_request
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `attest_ake` - must be in the auth pending state.
///
/// # Errors
///
/// * `LibMcError::AttestationVerificationFailed`
/// * `LibMcError::InvalidInput`
bool mc_attest_ake_process_auth_response(
  McAttestAke* MC_NONNULL attest_ake,
  const McBuffer* MC_NONNULL auth_response_data,
  const McVerifier* MC_NONNULL verifier,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

/* ==== Message Encryption ==== */

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_ciphertext` - must be null or else length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::Cipher`
ssize_t mc_attest_ake_encrypt(
  McAttestAke* MC_NONNULL attest_ake,
  const McBuffer* MC_NONNULL aad,
  const McBuffer* MC_NONNULL plaintext,
  McMutableBuffer* MC_NULLABLE out_ciphertext,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_plaintext` - length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::Cipher`
ssize_t mc_attest_ake_decrypt(
  McAttestAke* MC_NONNULL attest_ake,
  const McBuffer* MC_NONNULL aad,
  const McBuffer* MC_NONNULL ciphertext,
  McMutableBuffer* MC_NONNULL out_plaintext,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

#ifdef __cplusplus
}
#endif

#endif /* !ATTEST_H_ */

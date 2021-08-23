// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef TRANSACTION_H_
#define TRANSACTION_H_

#include "common.h"
#include "fog.h"
#include "keys.h"

/* ==================== Transaction ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Types ==== */

typedef struct {
  const McBuffer* MC_NONNULL commitment;
  uint64_t masked_value;
} McTxOutAmount;

typedef struct _McTransactionBuilderRing McTransactionBuilderRing;
typedef struct _McTransactionBuilder McTransactionBuilder;

/* ==== TxOut ==== */

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
bool mc_tx_out_matches_any_subaddress(
  const McTxOutAmount* MC_NONNULL tx_out_amount,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  bool* MC_NONNULL out_matches
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
bool mc_tx_out_matches_subaddress(
  const McBuffer* MC_NONNULL tx_out_target_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL subaddress_spend_private_key,
  bool* MC_NONNULL out_matches
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4, 5);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_tx_out_get_subaddress_spend_public_key(
  const McBuffer* MC_NONNULL tx_out_target_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  McMutableBuffer* MC_NONNULL out_subaddress_spend_public_key,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
bool mc_tx_out_get_value(
  const McTxOutAmount* MC_NONNULL tx_out_amount,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  uint64_t* MC_NONNULL out_value,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_key_image` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
bool mc_tx_out_get_key_image(
  const McBuffer* MC_NONNULL tx_out_target_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL subaddress_spend_private_key,
  McMutableBuffer* MC_NONNULL out_key_image,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4, 5);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
bool mc_tx_out_validate_confirmation_number(
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL tx_out_confirmation_number,
  const McBuffer* MC_NONNULL view_private_key,
  bool* MC_NONNULL out_valid
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/* ==== McTransactionBuilderRing ==== */

McTransactionBuilderRing* MC_NULLABLE mc_transaction_builder_ring_create();

void mc_transaction_builder_ring_free(
  McTransactionBuilderRing* MC_NULLABLE transaction_builder_ring
);

/// # Preconditions
///
/// * `tx_out_proto_bytes` - must be a valid binary-serialized `external.TxOut` Protobuf.
/// * `membership_proof_proto_bytes` - must be a valid binary-serialized
///     `external.TxOutMembershipProof` Protobuf.
bool mc_transaction_builder_ring_add_element(
  McTransactionBuilderRing* MC_NONNULL transaction_builder_ring,
  const McBuffer* MC_NONNULL tx_out_proto_bytes,
  const McBuffer* MC_NONNULL membership_proof_proto_bytes
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

/* ==== McTransactionBuilder ==== */

McTransactionBuilder* MC_NULLABLE mc_transaction_builder_create(
  uint64_t fee,
  uint64_t tombstone_block,
  const McFogResolver* MC_NULLABLE fog_resolver
);

void mc_transaction_builder_free(
  McTransactionBuilder* MC_NULLABLE transaction_builder
);

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call to `build`.
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `subaddress_spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `real_index` - must be within bounds of `ring`.
/// * `ring` - `TxOut` at `real_index` must be owned by account keys.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_transaction_builder_add_input(
  McTransactionBuilder* MC_NONNULL transaction_builder,
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL subaddress_spend_private_key,
  size_t real_index,
  const McTransactionBuilderRing* MC_NONNULL ring,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 5);

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call to `build`.
/// * `recipient_address` - must be a valid `PublicAddress`.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
McData* MC_NULLABLE mc_transaction_builder_add_output(
  McTransactionBuilder* MC_NONNULL transaction_builder,
  uint64_t amount,
  const McPublicAddress* MC_NONNULL recipient_address,
  McRngCallback* MC_NULLABLE rng_callback,
  McMutableBuffer* MC_NONNULL out_tx_out_confirmation_number,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 3, 6);

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call to `build`.
/// * `recipient_address` - must be a valid `PublicAddress`.
/// * `fog_hint_address` - must be a valid `PublicAddress` with `fog_info`.
/// * `out_tx_out_confirmation_number` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
McData* MC_NULLABLE mc_transaction_builder_add_output_with_fog_hint_address(
  McTransactionBuilder* MC_NONNULL transaction_builder,
  uint64_t amount,
  const McPublicAddress* MC_NONNULL recipient_address,
  const McPublicAddress* MC_NONNULL fog_hint_address,
  McRngCallback* MC_NULLABLE rng_callback,
  McMutableBuffer* MC_NONNULL out_tx_out_confirmation_number,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 3, 4, 5, 7);

/// # Preconditions
///
/// * `transaction_builder` - must not have been previously consumed by a call to `build`.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
McData* MC_NULLABLE mc_transaction_builder_build(
  McTransactionBuilder* MC_NONNULL transaction_builder,
  McRngCallback* MC_NULLABLE rng_callback,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* !TRANSACTION_H_ */

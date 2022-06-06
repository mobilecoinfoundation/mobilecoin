// Copyright (c) 2018-2022 The MobileCoin Foundation

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
  uint64_t masked_value;
  const McBuffer* MC_NONNULL masked_token_id;
} McTxOutMaskedAmount;

typedef struct {
  uint64_t value;
  uint64_t token_id;
} McTxOutAmount;

typedef struct _McTransactionBuilderRing McTransactionBuilderRing;
typedef struct _McTransactionBuilder McTransactionBuilder;
typedef struct _McTxOutMemoBuilder McTxOutMemoBuilder;

/* ==== TxOut ==== */

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
bool mc_tx_out_get_shared_secret(
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  McMutableBuffer* MC_NONNULL out_shared_secret,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::TransactionCrypto`
bool mc_tx_out_reconstruct_commitment(
  const McTxOutMaskedAmount* MC_NONNULL tx_out_masked_amount,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  McMutableBuffer* MC_NONNULL out_commitment,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/// # Preconditions
///
/// * `tx_out_commitment` - must be a valid CompressedCommitment
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_tx_out_commitment_crc32(
  const McBuffer* MC_NONNULL tx_out_commitment,
  uint32_t* MC_NONNULL out_crc32,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

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
bool mc_tx_out_get_amount(
  const McTxOutMaskedAmount* MC_NONNULL tx_out_masked_amount,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McBuffer* MC_NONNULL view_private_key,
  McTxOutAmount* MC_NONNULL out_amount,
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
  uint64_t token_id,
  uint64_t tombstone_block,
  const McFogResolver* MC_NULLABLE fog_resolver,
  McTxOutMemoBuilder* MC_NONNULL memo_builder,
  uint32_t block_version
)
MC_ATTRIBUTE_NONNULL(5);

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
  McMutableBuffer* MC_NONNULL out_tx_out_shared_secret,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 3, 5, 6);

/// # Preconditions
///
/// * `account_kay` - must be a valid account key, default change address computed from account key
/// * `transaction_builder` - must not have been previously consumed by a call
///   to `build`.
/// * `out_tx_out_confirmation_number` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::AttestationVerification`
/// * `LibMcError::InvalidInput`
McData* MC_NULLABLE mc_transaction_builder_add_change_output(
  const McAccountKey* MC_NONNULL account_key,
  McTransactionBuilder* MC_NONNULL transaction_builder,
  uint64_t amount,
  McRngCallback* MC_NULLABLE rng_callback,
  McMutableBuffer* MC_NONNULL out_tx_out_confirmation_number,
  McMutableBuffer* MC_NONNULL out_tx_out_shared_secret,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 4, 6);

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


/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
McTxOutMemoBuilder* MC_NULLABLE mc_memo_builder_sender_and_destination_create(
  const McAccountKey* MC_NONNULL account_key)
MC_ATTRIBUTE_NONNULL(1);

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
McTxOutMemoBuilder* MC_NULLABLE mc_memo_builder_sender_payment_request_and_destination_create(
  uint64_t payment_request_id,
  const McAccountKey* MC_NONNULL account_key
)
MC_ATTRIBUTE_NONNULL(2);

McTxOutMemoBuilder* MC_NULLABLE mc_memo_builder_default_create();


void mc_memo_builder_free(
  McTxOutMemoBuilder* MC_NULLABLE memo_builder
);


/* ==== SenderMemo ==== */

/// # Preconditions
///
/// * `sender_memo_data` - must be 64 bytes
/// * `sender_public_address` - must be a valid `PublicAddress`.
/// * `receiving_subaddress_view_private_key` - must be a valid
///     32-byte Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_memo_is_valid(
  const McBuffer* MC_NONNULL sender_memo_data,
  const McPublicAddress* MC_NONNULL sender_public_address,
  const McBuffer* MC_NONNULL receiving_subaddress_view_private_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  bool* MC_NONNULL out_valid,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4, 5);

/// # Preconditions
///
/// * `sender_account_key` - must be a valid account key
/// * `recipient_subaddress_view_public_key` - must be a valid
///     32-byte Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_memo_create(
  const McAccountKey* MC_NONNULL sender_account_key,
  const McBuffer* MC_NONNULL recipient_subaddress_view_public_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  McMutableBuffer* MC_NONNULL out_memo_data,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);

/// # Preconditions
///
/// * `sender_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_memo_get_address_hash(
  const McBuffer* MC_NONNULL sender_memo_data,
  McMutableBuffer* MC_NONNULL out_short_address_hash,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);


/* ==== DestinationMemo ==== */

/// # Preconditions
///
/// * `destination_public_address` - must be a valid 32-byte
///     Ristretto-format scalar.
/// * `number_of_recipients` - must be > 0
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_destination_memo_create(
  const McPublicAddress* MC_NONNULL destination_public_address,
  uint8_t number_of_recipients,
  uint64_t fee,
  uint64_t total_outlay,
  McMutableBuffer* MC_NONNULL out_memo_data,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 5);

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_destination_memo_get_address_hash(
  const McBuffer* MC_NONNULL destination_memo_data,
  McMutableBuffer* MC_NONNULL out_short_address_hash,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_destination_memo_get_number_of_recipients(
  const McBuffer* MC_NONNULL destination_memo_data,
  uint8_t* MC_NONNULL out_number_of_recipients,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_destination_memo_get_fee(
  const McBuffer* MC_NONNULL destination_memo_data,
  uint64_t* MC_NONNULL out_fee,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `destination_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_destination_memo_get_total_outlay(
  const McBuffer* MC_NONNULL destination_memo_data,
  uint64_t* MC_NONNULL out_total_outlay,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);


/* ==== SenderWithPaymentRequestMemo ==== */


/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
/// * `sender_public_address` - must be a valid `PublicAddress`.
/// * `receiving_subaddress_view_private_key` - must be a valid
///     32-byte Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_with_payment_request_memo_is_valid(
  const McBuffer* MC_NONNULL sender_with_payment_request_memo_data,
  const McPublicAddress* MC_NONNULL sender_public_address,
  const McBuffer* MC_NONNULL receiving_subaddress_view_private_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  bool* MC_NONNULL out_valid,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4, 5);

/// # Preconditions
///
/// * `sender_account_key` - must be a valid account key
/// * `recipient_subaddress_view_public_key` - must be a valid
///     32-byte Ristretto-format scalar.
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_memo_data` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_with_payment_request_memo_create(
  const McAccountKey* MC_NONNULL sender_account_key,
  const McBuffer* MC_NONNULL recipient_subaddress_view_public_key,
  const McBuffer* MC_NONNULL tx_out_public_key,
  uint64_t payment_request_id,
  McMutableBuffer* MC_NONNULL out_memo_data,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 5);

/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
/// * `out_short_address_hash` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_with_payment_request_memo_get_address_hash(
  const McBuffer* MC_NONNULL sender_with_payment_request_memo_data,
  McMutableBuffer* MC_NONNULL out_short_address_hash,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `sender_with_payment_request_memo_data` - must be 64 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_sender_with_payment_request_memo_get_payment_request_id(
  const McBuffer* MC_NONNULL sender_with_payment_request_memo_data,
  uint64_t* MC_NONNULL out_payment_request_id,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);


/* ==== Decrypt Memo Payload ==== */


/// # Preconditions
///
/// * `encrypted_memo` - must be 66 bytes
/// * `tx_out_public_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `account_key` - must be a valid account key
/// * `out_memo_payload` - length must be >= 16 bytes
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_memo_decrypt_e_memo_payload(
  const McBuffer* MC_NONNULL encrypted_memo,
  const McBuffer* MC_NONNULL tx_out_public_key,
  const McAccountKey* MC_NONNULL account_key,
  McMutableBuffer* MC_NONNULL out_memo_data,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3, 4);


#ifdef __cplusplus
}
#endif

#endif /* !TRANSACTION_H_ */

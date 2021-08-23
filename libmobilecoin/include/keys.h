// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef KEYS_H_
#define KEYS_H_

#include "common.h"

/* ==================== Account Keys ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Types ==== */

typedef struct {
  const char* MC_NONNULL report_url;
  const char* MC_NONNULL report_id;
  const McBuffer* MC_NONNULL authority_fingerprint;
} McAccountKeyFogInfo;

typedef struct {
  const McBuffer* MC_NONNULL view_private_key;
  const McBuffer* MC_NONNULL spend_private_key;
  const McAccountKeyFogInfo* MC_NULLABLE fog_info;
} McAccountKey;

typedef struct {
  const char* MC_NONNULL report_url;
  const char* MC_NONNULL report_id;
  const McBuffer* MC_NONNULL authority_sig;
} McPublicAddressFogInfo;

typedef struct {
  const McBuffer* MC_NONNULL view_public_key;
  const McBuffer* MC_NONNULL spend_public_key;
  const McPublicAddressFogInfo* MC_NULLABLE fog_info;
} McPublicAddress;

/* ==== AccountKey ==== */

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_view_private_key` - length must be >= 32.
/// * `out_subaddress_spend_private_key` - length must be >= 32.
bool mc_account_key_get_subaddress_private_keys(
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL spend_private_key,
  uint64_t subaddress_index,
  McMutableBuffer* MC_NONNULL out_subaddress_view_private_key,
  McMutableBuffer* MC_NONNULL out_subaddress_spend_private_key
)
MC_ATTRIBUTE_NONNULL(1, 2, 4, 5);

/// # Preconditions
///
/// * `view_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `spend_private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_subaddress_view_public_key` - length must be >= 32.
/// * `out_subaddress_spend_public_key` - length must be >= 32.
bool mc_account_key_get_public_address_public_keys(
  const McBuffer* MC_NONNULL view_private_key,
  const McBuffer* MC_NONNULL spend_private_key,
  uint64_t subaddress_index,
  McMutableBuffer* MC_NONNULL out_subaddress_view_public_key,
  McMutableBuffer* MC_NONNULL out_subaddress_spend_public_key
)
MC_ATTRIBUTE_NONNULL(1, 2, 4, 5);

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
/// * `out_fog_authority_fingerprint_sig` - length must be >= 64.
bool mc_account_key_get_public_address_fog_authority_sig(
  const McAccountKey* MC_NONNULL account_key,
  uint64_t subaddress_index,
  McMutableBuffer* MC_NONNULL out_fog_authority_sig
)
MC_ATTRIBUTE_NONNULL(1, 3);

#ifdef __cplusplus
}
#endif

#endif /* !KEYS_H_ */

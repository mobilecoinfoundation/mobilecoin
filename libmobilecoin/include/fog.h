// Copyright (c) 2018-2021 The MobileCoin Foundation

#ifndef FOG_H_
#define FOG_H_

#include "common.h"
#include "keys.h"

/* ==================== Fog ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== Types ==== */

typedef struct _McFogResolver McFogResolver;

typedef struct _McFullyValidatedFogPubkey McFullyValidatedFogPubkey;

typedef struct _McFogRng McFogRng;

/* ==== McFogResolver ==== */

McFogResolver* MC_NULLABLE mc_fog_resolver_create(
  const McVerifier* MC_NONNULL fog_report_verifier
)
MC_ATTRIBUTE_NONNULL(1);

void mc_fog_resolver_free(
  McFogResolver* MC_NULLABLE fog_resolver
);

McFullyValidatedFogPubkey* MC_NULLABLE mc_fog_resolver_get_fog_pubkey(
    const McFogResolver* MC_NONNULL fog_resolver,
    const McPublicAddress* MC_NONNULL recipient,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

McFullyValidatedFogPubkey* MC_NULLABLE mc_fog_resolver_get_fog_pubkey_from_protobuf_public_address(
    const McFogResolver* MC_NONNULL fog_resolver,
    const McBuffer* MC_NONNULL recipient_protobuf,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `report_url` - must be a nul-terminated C string containing a valid Fog report uri.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_fog_resolver_add_report_response(
  McFogResolver* MC_NONNULL fog_resolver,
  const char* MC_NONNULL report_url,
  const McBuffer* MC_NONNULL report_response,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2, 3);

/* ==== McFullyValidatedFogPubkey ==== */

void mc_fully_validated_fog_pubkey_free(
    McFullyValidatedFogPubkey* MC_NULLABLE fully_validated_fog_pubkey
);

/// # Preconditions
///
/// * `out_pubkey` - length must be >= 32.
bool mc_fully_validated_fog_pubkey_get_pubkey(
    const McFullyValidatedFogPubkey* MC_NONNULL fully_validated_fog_pubkey,
    McMutableBuffer* MC_NONNULL out_pubkey
);

uint64_t mc_fully_validated_fog_pubkey_get_pubkey_expiry(
    const McFullyValidatedFogPubkey* MC_NONNULL fully_validated_fog_pubkey
);

/* ==== McFogRng ==== */

/// # Preconditions
///
/// * `subaddress_view_private_key` - must be a valid 32-byte Ristretto-format scalar.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
McFogRng* MC_NULLABLE mc_fog_rng_create(
  const McBuffer* MC_NONNULL subaddress_view_private_key,
  const McBuffer* MC_NONNULL rng_public_key,
  uint32_t rng_version,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 2);

void mc_fog_rng_free(
  McFogRng* MC_NULLABLE fog_rng);

McFogRng* MC_NULLABLE mc_fog_rng_clone(
  const McFogRng* MC_NONNULL fog_rng
)
MC_ATTRIBUTE_NONNULL(1);

/// # Preconditions
///
/// * `out_fog_rng_proto_bytes` - must be null or else length must be >= `encoded.len`.
ssize_t mc_fog_rng_serialize_proto(
  const McFogRng* MC_NONNULL fog_rng,
  McMutableBuffer* MC_NULLABLE out_fog_rng_proto_bytes
)
MC_ATTRIBUTE_NONNULL(1);

/// # Errors
///
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
McFogRng* MC_NULLABLE mc_fog_rng_deserialize_proto(
  const McBuffer* MC_NONNULL fog_rng_proto_bytes,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1);

int64_t mc_fog_rng_index(
  const McFogRng* MC_NONNULL fog_rng
)
MC_ATTRIBUTE_NONNULL(1);

ssize_t mc_fog_rng_get_output_len(
  const McFogRng* MC_NONNULL fog_rng
)
MC_ATTRIBUTE_NONNULL(1);

/// # Preconditions
///
/// * `out_output` - length must be >= `output.len`.
bool mc_fog_rng_peek(
  const McFogRng* MC_NONNULL fog_rng,
  McMutableBuffer* MC_NONNULL out_output
)
MC_ATTRIBUTE_NONNULL(1, 2);

/// # Preconditions
///
/// * `out_output` - must be null or else length must be >= `output.len`.
bool mc_fog_rng_advance(
  McFogRng* MC_NONNULL fog_rng,
  McMutableBuffer* MC_NULLABLE out_output
)
MC_ATTRIBUTE_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* !FOG_H_ */

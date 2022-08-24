// Copyright (c) 2018-2022 The MobileCoin Foundation

#ifndef MC_CHACHA20_RNG_H_
#define MC_CHACHA20_RNG_H_

#include "common.h"

/* ==================== ChaCha20Rng ==================== */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ChaCha20Rng ChaCha20Rng;

/// Returns a new ChaCha20Rng instance initialized with the
/// seed value provided by the u64 long_val parameter
///
/// # Arguments
///
/// * `long_val` - an unsigned 64 bit value to use as the rng seed
///
/// # Errors
///
/// * `LibMcError::Poison`
ChaCha20Rng* MC_NULLABLE mc_chacha20_rng_create_with_long(
    uint64_t value,
    McError* MC_NULLABLE * MC_NULLABLE out_error
);

/// Returns a new ChaCha20Rng instance initialized with the
/// seed value provided by the bytes data, which must be at
/// least 32 bytes (only the first 32 bytes will be used)
///
/// # Arguments
///
/// * `bytes` - 32 bytes of data to use as the rng seed
///
/// # Errors
///
/// * `LibMcError::Poison`
ChaCha20Rng* MC_NULLABLE mc_chacha20_rng_create_with_bytes(
    const McBuffer* MC_NONNULL bytes,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1);

/// Returns the current word_pos of the ChaCha20Rng instance
///
/// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
/// * `out_word_pos` - pointer to buffer of 16 bytes where the current
///   chacha20_rng wordpos will be returned
///
/// # Errors
///
/// * `LibMcError::Poison`
bool mc_chacha20_rng_get_word_pos(
    ChaCha20Rng* MC_NONNULL chacha20_rng,
    const McBuffer* MC_NONNULL out_word_pos,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1,2);

/// Sets the current word_pos of the ChaCha20Rng instance
///
/// /// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
/// * `out_word_pos` - pointer to buffer of 128 bytes where the current
///   chacha20_rng wordpos will be returned
///
/// # Errors
///
/// * `LibMcError::Poison`
bool mc_chacha20_rng_set_word_pos(
    ChaCha20Rng* MC_NONNULL chacha20_rng,
    const McBuffer* MC_NONNULL bytes,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1,2);

/// Returns the next random u64 value from the ChaCha20Rng
///
/// /// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
///
/// # Errors
///
/// * `LibMcError::Poison`
uint64_t mc_chacha20_rng_next_long(
    ChaCha20Rng* MC_NONNULL chacha20_rng,
    McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1);

/// Frees the ChaCha20Rng
///
/// # Preconditions
/// 
/// * The ChaCha20Rng is no longer in use
/// 
/// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
void mc_chacha20_rng_free(
    ChaCha20Rng* MC_NULLABLE chacha20_rng
);

#ifdef __cplusplus
}
#endif

#endif /* MC_CHACHA20_RNG_H_ */

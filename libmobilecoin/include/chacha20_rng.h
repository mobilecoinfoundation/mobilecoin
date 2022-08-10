// Copyright (c) 2018-2022 The MobileCoin Foundation

#ifndef MC_CHACHA20_RNG_H_
#define MC_CHACHA20_RNG_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ChaCha20Rng ChaCha20Rng;

ChaCha20Rng* MC_NULLABLE mc_chacha20_rng_create_with_long(uint64_t value);

ChaCha20Rng* MC_NULLABLE mc_chacha20_rng_create_with_bytes(const McBuffer* MC_NONNULL bytes)
MC_ATTRIBUTE_NONNULL(1);

void mc_chacha20_rng_get_word_pos(ChaCha20Rng* MC_NULLABLE chacha20_rng, const McBuffer* MC_NONNULL out_word_pos)
MC_ATTRIBUTE_NONNULL(1,2);

void mc_chacha20_set_word_pos(ChaCha20Rng* MC_NULLABLE chacha20_rng, const McBuffer* MC_NONNULL bytes)
MC_ATTRIBUTE_NONNULL(1,2);

uint64_t mc_chacha20_rng_next_long(ChaCha20Rng* MC_NULLABLE chacha20_rng)
MC_ATTRIBUTE_NONNULL(1);

void mc_chacha20_rng_free(ChaCha20Rng* MC_NULLABLE chacha20_rng)
MC_ATTRIBUTE_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* MC_CHACHA20_RNG_H_ */

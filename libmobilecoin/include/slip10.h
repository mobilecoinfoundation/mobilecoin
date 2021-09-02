#ifndef SLIP10_H_
#define SLIP10_H_

#include "common.h"

/* ==================== SLIP10 ==================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ==== McSlip10 ==== */

/// # Preconditions
///
/// * `mnemonic` - must be a nul-terminated C string containing valid UTF-8.
/// * `out_view_private_key` - length must be >= 32.
/// * `out_spend_private_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
bool mc_slip10_account_private_keys_from_mnemonic(
  const char* MC_NONNULL mnemonic,
  uint32_t account_index,
  McMutableBuffer* MC_NONNULL out_view_private_key,
  McMutableBuffer* MC_NONNULL out_spend_private_key,
  McError* MC_NULLABLE * MC_NULLABLE out_error
)
MC_ATTRIBUTE_NONNULL(1, 3, 4);

#ifdef __cplusplus
}
#endif

#endif /* !SLIP10_H_ */

export type AuditedMintResponse = {
  mobUsd: {
    nonce_hex: string
    amount: string
    recipient_b58_addr: string
    token_id: string
    block_index: string
  }
  gnosis: {
    amount: string
    safe_addr: string
    token_addr: string
    expected_nonce_hex: string
  }
}

export type AuditedBurnResponse = {
  mobUsd: {
    amount: string
    sender_b58_addr: string
    tx_out_hex: string
    token_id: string
    block_index: string
  }
  gnosis: {
    amount: string
    safe_addr: string
    token_addr: string
    expected_tx_out_hex: string
  }
}

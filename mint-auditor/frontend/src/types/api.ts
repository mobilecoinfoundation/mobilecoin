export type TAuditedMintResponse = {
  audited: {
    id?: number
    mint_tx_id: number
    gnosis_safe_deposit_id: number
  } //pub struct AuditedMint
  mint: {
    id?: number
    block_index: number
    token_id: number
    amount: number
    nonce_hex: string
    recipient_b58_addr: string
    tombstone_block: number
    protobuf: number[]
    mint_config_id?: number
  } //pub struct MintTx
  deposit: {
    id?: number
    eth_tx_hash: string //SqlEthTxHash
    eth_block_number: number
    safe_addr: string //SqlEthAddr
    token_addr: string //SqlEthAddr
    amount: number
    expected_mc_mint_tx_nonce_hex: string
  } //pub struct GnosisSafeDeposit
}

export type TAuditedBurnResponse = {
  audited: {
    id?: number
    burn_tx_out_id: number
    gnosis_safe_withdrawal_id: number
  } //pub struct AuditedBurn
  burn: {
    id?: number
    block_index: number
    token_id: number
    amount: number
    public_key_hex: string
    protobuf: number[]
  } //pub struct BurnTxOut
  withdrawal: {
    id?: number
    eth_tx_hash: string //SqlEthTxHash
    eth_block_number: number
    safe_addr: string //SqlEthAddr
    token_addr: string //SqlEthAddr
    amount: number
    mc_tx_out_public_key_hex: string
  } //pub struct GnosisSafeWithdrawal
}

// from `GET /v1/safes/{address}/balances/usd` at https://safe-transaction.gnosis.io/
export type TGnosisSafeUsdBalanceResponse = {
  tokenAddress: string
  token: TErc20Info
  balance: string
  ethValue: string
  timestamp: string
  fiatBalance: string
  fiatConversion: string
  fiatCode: string
}

export type TErc20Info = {
  name: string
  symbol: string
  decimals: number
  logoUri: string
}

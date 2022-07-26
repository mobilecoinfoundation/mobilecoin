export type TAuditedBurn = {
  audited: {
    id?: number
    burnTxOutId: number
    gnosisSafeWithdrawalId: number
  }
  burn: TBurn
  withdrawal: TWithdrawal
}

export type TBurn = {
  id?: number
  blockIndex: number
  tokenId: number
  amount: number
  publicKeyHex: string
  protobuf: number[]
}

export type TWithdrawal = {
  id?: number
  ethTxHash: string
  ethBlockNumber: number
  safeAddr: string
  tokenAddr: string
  amount: number
  mcTxOutPublicKeyHex: string
}

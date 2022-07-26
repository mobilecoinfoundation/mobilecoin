export type TAuditedMint = {
  audited: {
    id?: number
    mintTxId: number
    gnosisSafeDepositId: number
  }
  mint: TMint
  deposit: TDeposit
}

export type TMint = {
  id?: number
  blockIndex: number
  tokenId: number
  amount: number
  nonceHex: string
  recipientB58Addr: string
  tombstoneBlock: number
  protobuf: number[]
  mintConfigId?: number
}

export type TDeposit = {
  id?: number
  ethTxHash: string
  ethBlockNumber: number
  safeAddr: string
  tokenAddr: string
  amount: number
  expectedMcMintTxNonceHex: string
}

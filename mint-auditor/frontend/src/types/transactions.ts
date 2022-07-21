export type MobUsdTransaction = {
  mobUsdAmount: number
  txoId: string
  memo: string
}
export type RsvTransaction = {
  rsvAmount: number
  rsvHash: string
}

export type TransactionPair = {
  type: string
  first: MobUsdTransaction | RsvTransaction
  second: MobUsdTransaction | RsvTransaction
  confirmed: boolean
}

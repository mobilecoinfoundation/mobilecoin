import axios from 'axios'
import _ from 'lodash'
import {
  TAuditedBurnResponse,
  TAuditedMintResponse,
  TAuditedBurn,
  TAuditedMint,
  TGnosisSafeUsdBalanceResponse,
  TLedgerBalance,
  TLedgerBalanceResponse,
} from '../types'

const mintAuditorUrl = 'http://localhost:7334'
const gnosisSafeUrl = 'https://safe-transaction.gnosis.io'

const paginate = (pageNumber: number): Record<string, number> => {
  const offset = pageNumber * 50
  const limit = 50

  return { offset, limit }
}

const get = async <T>(
  url: string,
  params?: Record<string, any>
): Promise<T> => {
  const response = await axios.get(url, { params })
  if (response.status >= 400) {
    console.error(
      `api failure: GET to ${url} responded with ${response.status}`
    )
  }
  return response.data as T
}

const camelCaseKeys = (
  jsonResponse: Record<string, any>
): Record<string, any> => {
  return _.transform(jsonResponse, (acc, value, key, target) => {
    const camelKey = _.isArray(target) ? key : _.camelCase(key)

    acc[camelKey] = _.isObject(value) ? camelCaseKeys(value) : value
  })
}

export const getAuditedMints = async (page: number): Promise<TAuditedMint> => {
  const { offset, limit } = paginate(page)
  const response = await get<TAuditedMintResponse>(
    mintAuditorUrl + '/audited_mints',
    { params: { offset, limit } }
  )
  return camelCaseKeys(response) as TAuditedMint
}

export const getAuditedBurns = async (page: number): Promise<TAuditedBurn> => {
  const { offset, limit } = paginate(page)
  const response = await get<TAuditedBurnResponse>(
    mintAuditorUrl + '/audited_burns',
    { params: { offset, limit } }
  )
  return camelCaseKeys(response) as TAuditedBurn
}

export const getGnosisSafeBalance = async (
  address: string
): Promise<string> => {
  const response = await get<TGnosisSafeUsdBalanceResponse>(
    gnosisSafeUrl + `/v1/safes/${address}/balances/usd`
  )
  return response.balance
}

export const getLedgerBalance = async (): Promise<TLedgerBalance> => {
  const response = await get<TLedgerBalanceResponse>(
    mintAuditorUrl + '/ledger_balance'
  )
  return camelCaseKeys(response) as TLedgerBalance
}

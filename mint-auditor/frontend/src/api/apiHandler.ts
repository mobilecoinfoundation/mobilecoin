import axios from 'axios'
import _ from 'lodash'
import {
  TAuditedBurnResponse,
  TAuditedMintResponse,
  TAuditedBurn,
  TAuditedMint,
} from '../types'

const url = 'http://localhost:7334'

const paginate = (pageNumber: number): Record<string, number> => {
  const offset = pageNumber * 50
  const limit = 50

  return { offset, limit }
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
  try {
    const response = await axios.get(url + '/audited_mints', {
      params: { offset, limit },
    })
    console.log(response)
    if ('data' in response) {
      return camelCaseKeys(
        response['data'] as TAuditedMintResponse
      ) as TAuditedMint
    } else {
      throw Error('unexpected json format')
    }
  } catch (err) {
    console.log(err)
    throw err
  }
}
export const getAuditedBurns = async (page: number): Promise<TAuditedBurn> => {
  const { offset, limit } = paginate(page)
  try {
    const response = await axios.get(url + '/audited_burns', {
      params: { offset, limit },
    })
    console.log(response)
    if ('data' in response) {
      return camelCaseKeys(
        response['data'] as TAuditedBurnResponse
      ) as TAuditedBurn
    } else {
      throw Error('unexpected json format')
    }
  } catch (err) {
    console.log(err)
    throw err
  }
}

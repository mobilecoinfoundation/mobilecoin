import axios from 'axios'
import _ from 'lodash'
import { AuditedBurnResponse, AuditedMintResponse } from '../types'

const url = 'https://datausa.io/api/data?drilldowns=Nation&measures=Population'

const camelCaseKeys = (
  jsonResponse: Record<string, any>
): Record<string, any> => {
  return _.transform(jsonResponse, (acc, value, key, target) => {
    const camelKey = _.isArray(target) ? key : _.camelCase(key)

    acc[camelKey] = _.isObject(value) ? camelCaseKeys(value) : value
  })
}

export type Nation = {
  idNation: string
  nation: string
  idYear: number
  year: string
  population: number
  slugNation: string
}

export const getNationData = async (): Promise<Nation[]> => {
  try {
    const response = await axios.get(url)
    if ('data' in response) {
      return camelCaseKeys(response['data']['data']) as Nation[]
    } else {
      throw Error('unexpected json format')
    }
  } catch (err) {
    console.log(err)
    throw err
  }
}

export const getAuditedMints = async (): Promise<AuditedMintResponse> => {
  try {
    const response = await axios.get(url)
    if ('data' in response) {
      return camelCaseKeys(response['data']) as AuditedMintResponse
    } else {
      throw Error('unexpected json format')
    }
  } catch (err) {
    console.log(err)
    throw err
  }
}

export const getAuditedBurns = async (): Promise<AuditedBurnResponse> => {
  try {
    const response = await axios.get(url)
    if ('data' in response) {
      return camelCaseKeys(response['data']) as AuditedBurnResponse
    } else {
      throw Error('unexpected json format')
    }
  } catch (err) {
    console.log(err)
    throw err
  }
}

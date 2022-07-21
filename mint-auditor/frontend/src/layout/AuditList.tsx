import React, { ReactElement, FC, useState, useEffect } from 'react'
import { Box } from '@mui/material'
import InfiniteScroll from 'react-infinite-scroll-component'
import { MobUsdTransaction, RsvTransaction, TransactionPair } from '../types'
import { TransactionItem } from '../components/TransactionItem'
import { getNationData, Nation } from '../api/apiHandler'

export const AuditList: FC<any> = (): ReactElement => {
  const [mints, setMints] = useState<TransactionPair[]>([])
  const [burns, setBurns] = useState<TransactionPair[]>([])

  useEffect(() => {
    const fetchData = async () => {
      await fetchMints()
      await fetchBurns()
    }
    fetchData()
  }, [])

  const fetchMints = async () => {
    const prevMints = mints
    const newTransactions = await getTestData()
    const newMints = newTransactions.filter(
      (transaction) => transaction.type === 'mint'
    )
    setMints(prevMints.concat(newMints))
  }

  const fetchBurns = async () => {
    const prevBurns = burns
    const newTransactions = await getTestData()
    const newBurns = newTransactions.filter(
      (transaction) => transaction.type === 'burn'
    )
    setBurns(prevBurns.concat(newBurns))
  }

  const generateTransactionFromNationData = (nation: Nation) => {
    const type = Math.round(Math.random()) ? 'mint' : 'burn'
    const amount = nation.population
    const rsvHash =
      Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)

    if (type === 'mint') {
      const first = {
        mobUsdAmount: amount,
        txoId: nation.idYear.toString(),
        memo: rsvHash,
      } as MobUsdTransaction
      const second = { rsvAmount: -1 * amount, rsvHash } as RsvTransaction
      return { type, first, second, confirmed: true }
    } else {
      const first = { rsvAmount: amount, rsvHash } as RsvTransaction
      const second = {
        mobUsdAmount: -1 * amount,
        txoId: nation.idYear.toString(),
        memo: rsvHash,
      } as MobUsdTransaction
      return { type, first, second, confirmed: true } as TransactionPair
    }
  }

  const getTestData = async (): Promise<TransactionPair[]> => {
    const nationData = await getNationData()
    const transactions = nationData.map((nation) =>
      generateTransactionFromNationData(nation)
    )
    return transactions
  }

  const style = {
    border: '1px solid green',
    margin: 6,
    padding: 8,
  }

  return (
    <Box
      sx={{
        flexGrow: 1,
        backgroundColor: 'whitesmoke',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      <div id="scrollableMints" style={{ maxHeight: 500, overflow: 'auto' }}>
        <InfiniteScroll
          dataLength={mints.length}
          next={fetchMints}
          hasMore={true}
          loader={<h4>Loading...</h4>}
          scrollableTarget="scrollableMints"
        >
          {mints.map((i, index) => (
            <div style={style} key={index}>
              <TransactionItem {...i.first} />
              <TransactionItem {...i.second} />
              {i.type}
              {i.confirmed}
            </div>
          ))}
        </InfiniteScroll>
      </div>
      <div id="scrollableBurns" style={{ maxHeight: 500, overflow: 'auto' }}>
        <InfiniteScroll
          dataLength={burns.length}
          next={fetchBurns}
          hasMore={true}
          loader={<h4>Loading...</h4>}
          scrollableTarget="scrollableBurns"
        >
          {burns.map((i, index) => (
            <div style={style} key={index}>
              <TransactionItem {...i.first} />
              <TransactionItem {...i.second} />
              {i.type}
              {i.confirmed}
            </div>
          ))}
        </InfiniteScroll>
      </div>
    </Box>
  )
}

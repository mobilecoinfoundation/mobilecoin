import React, { ReactElement, FC, useState, useEffect } from 'react'
import { Box, Grid, Typography } from '@mui/material'
import InfiniteScroll from 'react-infinite-scroll-component'
import { MobUsdTransaction, RsvTransaction, TransactionPair } from '../types'
import { getNationData, Nation } from '../api/apiHandler'
import { RowItem } from '../components/RowItem'

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
    let newMints = newTransactions.filter(
      (transaction) => transaction.type === 'mint'
    )
    while (newMints.length <= 50) {
      newMints = newMints.concat(newMints)
    }
    if (prevMints.length === 0) {
      newMints[0].second = undefined
    }
    setMints(prevMints.concat(newMints))
  }

  const fetchBurns = async () => {
    const prevBurns = burns
    const newTransactions = await getTestData()
    let newBurns = newTransactions.filter(
      (transaction) => transaction.type === 'burn'
    )
    while (newBurns.length <= 50) {
      newBurns = newBurns.concat(newBurns)
    }
    if (prevBurns.length === 0) {
      newBurns[0].second = undefined
    }
    setBurns(prevBurns.concat(newBurns))
  }

  const generateTransactionFromNationData = (
    nation: Nation
  ): TransactionPair => {
    const type = Math.round(Math.random()) ? 'mint' : 'burn'
    const amount = nation.population
    const rsvHash =
      Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)

    if (type === 'mint') {
      const first = { rsvAmount: amount, rsvHash } as RsvTransaction
      const second = {
        mobUsdAmount: amount,
        txoId: nation.idYear.toString(),
        memo: rsvHash,
      } as MobUsdTransaction
      return { type, first, second, confirmed: true }
    } else {
      // burn
      const first = {
        mobUsdAmount: amount,
        txoId: nation.idYear.toString(),
        memo: rsvHash,
      } as MobUsdTransaction
      const second = { rsvAmount: amount, rsvHash } as RsvTransaction
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

  return (
    <Box
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignContent: 'center',
        margin: '5vh auto',
      }}
    >
      <Grid
        container
        columnSpacing={1}
        rowSpacing={1}
        sx={{ maxWidth: '90vw' }}
      >
        <Grid item xs={6} sx={{ display: 'flex', justifyContent: 'center' }}>
          <Typography
            variant="h5"
            noWrap
            sx={{
              color: 'primary.contrastText',
              height: '30px',
            }}
          >
            Deposits
          </Typography>
        </Grid>
        <Grid item xs={6} sx={{ display: 'flex', justifyContent: 'center' }}>
          <Typography
            variant="h5"
            noWrap
            sx={{
              color: 'primary.contrastText',
              height: '30px',
            }}
          >
            Redeems
          </Typography>
        </Grid>
        <Grid item xs={6} sx={{ display: 'flex', justifyContent: 'center' }}>
          <div
            id="scrollableMints"
            style={{
              maxHeight: '75vh',
              maxWidth: 'calc(36vw + 74px)',
              overflow: 'auto',
              backgroundColor: '#fff',
              padding: 1,
              borderRadius: '5px',
              boxShadow: 'rgba(0, 0, 0, 1) 0px 5px 15px',
            }}
          >
            <InfiniteScroll
              dataLength={mints.length}
              next={fetchMints}
              hasMore={true}
              loader={<h4>Loading...</h4>}
              scrollableTarget="scrollableMints"
            >
              {mints.map((i, index) => (
                <RowItem {...i} key={index} />
              ))}
            </InfiniteScroll>
          </div>
        </Grid>
        <Grid item xs={6} sx={{ display: 'flex', justifyContent: 'center' }}>
          <div
            id="scrollableBurns"
            style={{
              maxHeight: '75vh',
              maxWidth: 'calc(36vw + 74px)',
              overflow: 'auto',
              backgroundColor: '#fff',
              padding: 1,
              borderRadius: '5px',
              boxShadow: 'rgba(0, 0, 0, 1) 0px 5px 15px',
            }}
          >
            <InfiniteScroll
              dataLength={burns.length}
              next={fetchBurns}
              hasMore={true}
              loader={<h4>Loading...</h4>}
              scrollableTarget="scrollableBurns"
            >
              {burns.map((i, index) => (
                <RowItem {...i} key={index} />
              ))}
            </InfiniteScroll>
          </div>
        </Grid>
      </Grid>
    </Box>
  )
}

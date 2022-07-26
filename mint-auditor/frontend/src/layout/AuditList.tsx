import React, { ReactElement, FC, useState, useEffect } from 'react'
import { Box, Grid, Typography } from '@mui/material'
import InfiniteScroll from 'react-infinite-scroll-component'
import { TAuditedBurn, TAuditedMint } from '../types'
import { getAuditedMints, getAuditedBurns } from '../api/apiHandler'
import { AuditedMint } from '../components/AuditedMint'
import { AuditedBurn } from '../components/AuditedBurn'

export const AuditList: FC<any> = (): ReactElement => {
  const [mints, setMints] = useState<TAuditedMint[]>([])
  const [burns, setBurns] = useState<TAuditedBurn[]>([])
  const [mintPage, setMintPage] = useState<number>(0)
  const [burnPage, setBurnPage] = useState<number>(0)

  useEffect(() => {
    const fetchData = async () => {
      await fetchMints()
      await fetchBurns()
    }
    fetchData()
  }, [])

  const fetchBurns = async () => {
    const newBurns = await getAuditedBurns(burnPage)
    setBurns(burns.concat(newBurns))
    setBurnPage(burnPage + 1)
  }

  const fetchMints = async () => {
    const newMints = await getAuditedMints(mintPage)
    setMints(mints.concat(newMints))
    setMintPage(mintPage + 1)
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
                <AuditedMint {...i} key={index} />
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
                <AuditedBurn {...i} key={index} />
              ))}
            </InfiniteScroll>
          </div>
        </Grid>
      </Grid>
    </Box>
  )
}

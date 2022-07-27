import { Box, Typography } from '@mui/material'
import React, { FC, useEffect, useState } from 'react'
import { getLedgerBalance } from '../api/apiHandler'
import { TLedgerBalance } from '../types'

export const LedgerBalance: FC = () => {
  const [ledgerBalance, setLedgerBalance] = useState<TLedgerBalance>()
  useEffect(() => {
    const getBalance = async () => {
      const balance = await getLedgerBalance()
      setLedgerBalance(balance)
    }
    getBalance()
  }, [])
  return (
    <Box sx={{ margin: 1 }}>
      <Typography sx={{ fontWeight: 'bold' }}>Ledger Balance</Typography>
      <Typography>mints - burns = total</Typography>
      {ledgerBalance ? (
        <Typography>
          {ledgerBalance.mintedTotal} - {ledgerBalance.burnedTotal} ={' '}
          {ledgerBalance.total}
        </Typography>
      ) : (
        <Typography>loading...</Typography>
      )}
    </Box>
  )
}

import { Box, Typography } from '@mui/material'
import React, { FC, useEffect, useState } from 'react'
import { getGnosisSafeBalance } from '../api/apiHandler'

export const GnosisSafe: FC = () => {
  const [balance, setBalance] = useState<string>()
  const address = '12345'
  useEffect(() => {
    const getBalance = async () => {
      const balance = await getGnosisSafeBalance(address)
      setBalance(balance)
    }
    getBalance()
  }, [])
  return (
    <Box sx={{ padding: 1 }}>
      <Typography sx={{ fontWeight: 'bold' }}>Gnosis Safe Balance</Typography>
      <Typography>Safe: {address}</Typography>
      <Typography>{balance || 'loading...'}</Typography>
    </Box>
  )
}

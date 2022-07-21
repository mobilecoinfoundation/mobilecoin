import { Box } from '@mui/material'
import { SettingsEthernet } from '@mui/icons-material'
import React, { FC } from 'react'
import { TransactionPair } from '../types'
import { TransactionItem } from './TransactionItem'

export const RowItem: FC<TransactionPair> = (
  transactionPair: TransactionPair
) => {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'row',
        boxShadow:
          'rgba(60, 64, 67, 0.3) 0px 1px 2px 0px, rgba(60, 64, 67, 0.15) 0px 2px 6px 2px',
        margin: '5px 5px 10px',
      }}
    >
      <TransactionItem {...transactionPair.first} />
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        <Box
          sx={{
            borderRadius: '50%',
            height: 30,
            width: 30,
            backgroundColor: 'primary.main',
            display: 'flex',
            justifyContent: 'center',
          }}
        >
          <SettingsEthernet
            sx={{
              color: 'secondary.light',
              margin: 'auto',
            }}
          />
        </Box>
      </Box>
      <TransactionItem {...transactionPair.second} />
    </Box>
  )
}

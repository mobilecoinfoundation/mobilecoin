import { Box } from '@mui/material'
import { PriceCheck, LinkOff } from '@mui/icons-material'
import React, { FC } from 'react'
import { TransactionPair } from '../types'
import { TransactionItem } from './TransactionItem'

export const RowItem: FC<TransactionPair> = (
  transactionPair: TransactionPair
) => {
  const isValid = transactionPair.first && transactionPair.second
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
      <TransactionItem
        transaction={transactionPair.first}
        type={transactionPair.type}
      />
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        {isValid ? (
          <Box
            sx={{
              borderRadius: '50%',
              height: 30,
              width: 30,
              backgroundColor: '#12a312',
              display: 'flex',
              justifyContent: 'center',
            }}
          >
            <PriceCheck
              sx={{
                color: 'secondary.light',
                margin: 'auto',
              }}
            />
          </Box>
        ) : (
          <Box
            sx={{
              borderRadius: '50%',
              height: 30,
              width: 30,
              backgroundColor: 'secondary.main',
              display: 'flex',
              justifyContent: 'center',
            }}
          >
            <LinkOff
              sx={{
                color: 'secondary.dark',
                margin: 'auto',
              }}
            />
          </Box>
        )}
      </Box>
      <TransactionItem
        transaction={transactionPair.second}
        type={transactionPair.type}
      />
    </Box>
  )
}

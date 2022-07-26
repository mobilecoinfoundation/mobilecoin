import { Box, Typography } from '@mui/material'
import React, { FC } from 'react'
import { MobUsdTransaction, RsvTransaction } from '../types'

type Props = {
  transaction?: MobUsdTransaction | RsvTransaction
  type: 'mint' | 'burn'
}

export const TransactionItem: FC<Props> = (props: {
  transaction?: MobUsdTransaction | RsvTransaction
  type: 'mint' | 'burn'
}) => {
  const { transaction, type } = props
  const style: React.CSSProperties = {
    borderRadius: 1,
    padding: 1,
    margin: 1,
    boxShadow:
      'rgba(67, 71, 85, 0.27) 0px 0px 0.25em, rgba(90, 125, 188, 0.05) 0px 0.25em 1em',
    width: '18vw',
  }

  const missingTransactionStyle: React.CSSProperties = {
    backgroundColor: 'darkgrey',
  }

  const noWrapStyle = {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    '&:hover': { overflow: 'visible' },
    textOverflow: 'ellipsis',
  }

  if (!transaction) {
    return (
      <Box sx={[style, missingTransactionStyle]}>
        <Typography sx={{ fontWeight: 'bold' }}>Pending Transaction</Typography>
      </Box>
    )
  }

  if ('rsvAmount' in transaction) {
    transaction as RsvTransaction

    return (
      <Box sx={style}>
        <Typography sx={{ fontWeight: 'bold' }}>
          Gnosis Safe {type === 'mint' ? 'Deposit' : 'Withdrawal'}
        </Typography>
        <Box>amount: {transaction.rsvAmount} RSV</Box>
        <Box sx={noWrapStyle}>hash: {transaction.rsvHash}</Box>
      </Box>
    )
  } else if ('mobUsdAmount' in transaction) {
    transaction as MobUsdTransaction
    return (
      <Box sx={style}>
        <Typography sx={{ fontWeight: 'bold' }}>
          MobileCoin Ledger {type === 'mint' ? 'Mint' : 'Burn'}
        </Typography>
        <Box>amount: {transaction.mobUsdAmount} mobUSD</Box>
        <Box sx={noWrapStyle}>hash: {transaction.txoId}</Box>
      </Box>
    )
  } else {
    return (
      <Box sx={[style, missingTransactionStyle]}>
        <Typography sx={{ fontWeight: 'bold' }}>
          Unrecognized transaction
        </Typography>
      </Box>
    )
  }
}

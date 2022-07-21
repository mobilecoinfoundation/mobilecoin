import Box from '@mui/material/Box'
import React, { FC } from 'react'
import { MobUsdTransaction, RsvTransaction } from '../types'
export const TransactionItem: FC<MobUsdTransaction | RsvTransaction> = (
  transaction: MobUsdTransaction | RsvTransaction
) => {
  const style: React.CSSProperties = {
    // border: 'solid',
    // borderWidth: 1,
    // borderColor: 'secondary.main',
    borderRadius: 1,
    padding: 1,
    margin: 1,
    boxShadow:
      'rgba(67, 71, 85, 0.27) 0px 0px 0.25em, rgba(90, 125, 188, 0.05) 0px 0.25em 1em',
    width: '18vw',
  }

  const noWrapStyle: React.CSSProperties = {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  }

  if ('rsvAmount' in transaction) {
    transaction as RsvTransaction
    return (
      <Box sx={style}>
        RSV Transaction
        <div>rsv transaction amount: {transaction.rsvAmount}</div>
        <div style={noWrapStyle}>rsv hash: {transaction.rsvHash}</div>
      </Box>
    )
  } else if ('mobUsdAmount' in transaction) {
    transaction as MobUsdTransaction
    return (
      <Box sx={style}>
        mobUSD Transaction
        <div>mobUSD transaction amount: {transaction.mobUsdAmount}</div>
        <div>mobUSD transaction hash: {transaction.txoId}</div>
        <div style={noWrapStyle}>rsv hash: {transaction.memo}</div>
      </Box>
    )
  } else {
    return <div>unidentified transaction</div>
  }
}

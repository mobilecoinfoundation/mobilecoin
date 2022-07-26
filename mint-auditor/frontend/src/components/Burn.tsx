import { Box, Typography } from '@mui/material'
import React, { FC } from 'react'
import { TBurn } from '../types'

export const Burn: FC<TBurn> = (Burn: TBurn) => {
  const style: React.CSSProperties = {
    borderRadius: 1,
    padding: 1,
    margin: 1,
    boxShadow:
      'rgba(67, 71, 85, 0.27) 0px 0px 0.25em, rgba(90, 125, 188, 0.05) 0px 0.25em 1em',
    width: '18vw',
  }

  const noWrapStyle = {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    '&:hover': { overflow: 'visible' },
    textOverflow: 'ellipsis',
  }

  return (
    <Box sx={style}>
      <Typography sx={{ fontWeight: 'bold' }}>
        MobileCoin Ledger Burn
      </Typography>
      <Box>amount: {Burn.amount} mobUSD</Box>
      <Box sx={noWrapStyle}>hash: {Burn.tokenId}</Box>
    </Box>
  )
}

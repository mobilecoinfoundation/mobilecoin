import { LinkOff, PriceCheck } from '@mui/icons-material'
import { Box } from '@mui/material'
import React, { FC } from 'react'
import { TAuditedBurn } from '../types'
import { Withdrawal } from './Withdrawal'
import { Burn } from './Burn'

export const AuditedBurn: FC<TAuditedBurn> = (auditedBurn: TAuditedBurn) => {
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
      <Withdrawal {...auditedBurn.withdrawal} />
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        {true ? ( // how does this get validated?
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
      <Burn {...auditedBurn.burn} />
    </Box>
  )
}

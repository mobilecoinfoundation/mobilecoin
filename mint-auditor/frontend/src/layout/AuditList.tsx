import React, { ReactElement, FC } from 'react'
import { Box, Typography } from '@mui/material'

export const AuditList: FC<any> = (): ReactElement => {
  return (
    <Box
      sx={{
        flexGrow: 1,
        backgroundColor: 'whitesmoke',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      <Typography variant="h3">Auditor List</Typography>
    </Box>
  )
}

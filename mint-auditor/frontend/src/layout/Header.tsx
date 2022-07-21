import React, { FC, ReactElement } from 'react'
import { Box, Container, Toolbar, Typography } from '@mui/material'
import { MCIcon } from '../components/icons'

export const Header: FC = (): ReactElement => {
  return (
    <>
      <Box
        sx={{
          width: '100%',
          height: '100px',
          // backgroundColor: 'primary.main',
          background:
            'linear-gradient(180deg, rgba(2,124,253,1) 0%, rgba(255,255,255,0) 100%)',
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
        }}
      >
        <Container maxWidth={false}>
          <Toolbar disableGutters>
            {MCIcon('#000')}
            <Typography
              variant="h4"
              noWrap
              sx={{
                mr: 2,
                display: { xs: 'none', md: 'flex' },
                color: 'secondary.contrastText',
                paddingLeft: 2,
              }}
            >
              MobileCoin Auditor
            </Typography>
          </Toolbar>
        </Container>
      </Box>
      {/* <Box
        sx={{
          width: '100%',
          height: 10,
          background:
            'linear-gradient(180deg, rgba(2,124,253,1) 0%, rgba(255,255,255,0) 100%)',
        }}
      ></Box> */}
    </>
  )
}

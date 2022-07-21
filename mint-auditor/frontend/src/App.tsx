import React from 'react'
import { Box, CssBaseline, ThemeProvider } from '@mui/material'
import { createTheme } from '@mui/material/styles'
import { Header } from './layout/Header'
import { AuditList } from './layout/AuditList'

export const App = () => {
  const theme = createTheme({
    palette: {
      primary: {
        // mobilecoin blue
        light: '#0c90e6',
        main: '#027cfd',
        dark: '#0082d6',
        contrastText: '#fff',
      },
      secondary: {
        // mobilecoin grayscale
        main: '#f0f0f0',
        light: '#fff',
        dark: '#000',
        contrastText: '#000',
      },
    },
  })

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box
        sx={{
          height: '100vh',
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: 'secondary.main',
        }}
      >
        <Header />
        <AuditList />
      </Box>
    </ThemeProvider>
  )
}

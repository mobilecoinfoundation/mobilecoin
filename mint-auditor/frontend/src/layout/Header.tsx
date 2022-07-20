import React, { FC, ReactElement } from "react"
import { Box, Container, Toolbar, Typography } from "@mui/material"
import { MCIcon } from "../components/icons"

export const Header: FC = (): ReactElement => {
  return (
    <>
      <Box
        sx={{
          width: "100%",
          height: "auto",
          backgroundColor: "primary.main",
        }}
      >
        <Container maxWidth="xl">
          <Toolbar disableGutters>
            {MCIcon("#000")}
            <Typography
              variant="h6"
              noWrap
              sx={{
                mr: 2,
                display: { xs: "none", md: "flex" },
                color: "primary.contrastText",
                paddingLeft: 2,
              }}
            >
              MobileCoin Auditor
            </Typography>
          </Toolbar>
        </Container>
      </Box>
      <Box>{/* blue gradient below solid blue bar header */}</Box>
    </>
  )
}

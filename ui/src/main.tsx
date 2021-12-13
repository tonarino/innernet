import React from 'react'
import ReactDOM from 'react-dom'
import { ChakraProvider } from '@chakra-ui/react'
import { AppRouter } from './routes'
import './index.css'


ReactDOM.render(
  <React.StrictMode>
    <ChakraProvider>
      <AppRouter />
    </ChakraProvider>
  </React.StrictMode>,
  document.getElementById('root')
)
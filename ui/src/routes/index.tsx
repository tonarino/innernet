import { BrowserRouter, Redirect, Route } from 'react-router-dom'

import SeverPage from '../pages/server'
import ConfigPage from '../pages/config'

import { PrivateRoute } from './utils'

export const AppRouter = () => {

  return (
    <BrowserRouter basename="/ui">
      <Redirect exact from="/" to="/auth" />
      <PrivateRoute path="/server" component={SeverPage} />
      <Route path="/auth" component={ConfigPage} />
    </BrowserRouter>
  )
}

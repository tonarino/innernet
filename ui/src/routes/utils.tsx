import * as React from 'react'
import { Route, Redirect, RouteComponentProps } from 'react-router-dom'
import type { RouteProps } from 'react-router-dom'

interface PrivateRouteParams extends RouteProps {
  component:
  | React.ComponentType<RouteComponentProps<any>>
  | React.ComponentType<any>
}

export function PrivateRoute({
  component: Component,
  ...rest
}: PrivateRouteParams) {


  return (
    <Route
      {...rest}
      render={(props) =>
        true ? (
          <Component {...props} />
        ) : (
          <Redirect
            to={{
              pathname: '/auth',
              state: { from: props.location },
            }}
          />
        )
      }
    />
  )
}

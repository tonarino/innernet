# Innernet ui

This repository contains a front for innernet that will be bundled in the binary and served under the path:

> http://innernet-server.your_interface:port/ui

## Status

This is a proof of concept 

// TODO

- separate /user and  /admin pages
- create components for peer, cidr, state, associations...
- create crud views for admin


## Generate bindings

```sh
./generate-ts-bindings.sh
```

## Commands

```sh
yarn build
yarn dev
yarn serve
```

## yarn resolution:
see
https://github.com/chakra-ui/chakra-ui/issues/5082
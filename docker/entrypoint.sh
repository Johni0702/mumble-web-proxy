#!/usr/bin/env bash

cmd=("/mumble-web-proxy" "--listen-ws=$MWP_LISTEN_WS" "--server=$MWP_SERVER")

if [ "$MWP_ACCEPT_INVALID_CERTIFICATE" = true ]; then
  cmd+=("--accept-invalid-certificate")
fi

if [ -n "$MWP_ICE_PORT_MIN" ]; then
  cmd+=("--ice-port-min=$MWP_ICE_PORT_MIN")
fi

if [ -n "$MWP_ICE_PORT_MAX" ]; then
  cmd+=("--ice-port-max=$MWP_ICE_PORT_MAX")
fi

if [ -n "$MWP_ICE_IPV4" ]; then
  cmd+=("--ice-ipv4=$MWP_ICE_IPV4")
fi

if [ -n "$MWP_ICE_IPV6" ]; then
  cmd+=("--ice-ipv6=$MWP_ICE_IPV6")
fi

exec "${cmd[@]}"

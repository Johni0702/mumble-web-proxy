#!/bin/bash

CMD="./mumble-web-proxy --listen-ws $LISTEN_WS --server $MUMBLE_SERVER"

if [ -n "$ICE_PORT_MIN" ]; then
  CMD="$CMD --ice-port-min $ICE_PORT_MIN"
fi

if [ -n "$ICE_PORT_MAX" ]; then
  CMD="$CMD --ice-port-max $ICE_PORT_MAX"
fi

if [ -n "$ICE_IPV4" ]; then
  CMD="$CMD --ice-ipv4 $ICE_IPV4";
fi

if [ -n "$ICE_IPV6" ]; then
  CMD="$CMD --ice-ipv6 $ICE_IPV6";
fi

eval "$CMD"

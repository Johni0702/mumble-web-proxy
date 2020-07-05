# mumble-web-proxy

mumble-web-proxy is a [Mumble] to WebSocket+WebRTC proxy.

The Mumble protocol uses TCP for control and UDP for voice.
This proxy bridges those to WebSocket for control and WebRTC for voice.

While not limited to, its primary use-case is allowing [mumble-web] to connect to vanilla Mumble 1.2/1.3 servers.

Note that it requires an extension to the Mumble protocol which has not yet been stabilized and as such may change at any time, so make sure to keep mumble-web and mumble-web-proxy in sync.

### Installing

#### Prerequisites

- Rust 1.39+ (e.g. via [rustup](https://rustup.rs/))
- libnice development headers (`libnice-devel` on Fedora, `libnice-dev` on Debian)
- OpenSSL development headers (`openssl-devel` on Fedora, `libssl-dev` on Debian)
- clang (`clang` on Fedora and Debian)

#### Building
For now, mumble-web-proxy must be built from source. Pre-built binaries may be provided at a later point in development.

Make sure you have Cargo (Rust's package manager) installed (e.g. via [rustup](https://rustup.rs/)), then run:
```
git clone https://github.com/johni0702/mumble-web-proxy
cd mumble-web-proxy
cargo build --release
```
The final binary will be at `target/release/mumble-web-proxy`.

#### Running

mumble-web-proxy can only accept insecure websocket connections, so you will want to run it behind some web server which can terminate TLS. See [mumble-web]'s README for an example.

Run `mumble-web-proxy --help` to see available options.
E.g. if you want the proxy to listen on port `64737` and connect to your Mumble server at `mumbleserver:64738`, run:
```
mumble-web-proxy --listen-ws 64737 --server mumbleserver:64738
```

Instead of specifying all the options directly in the arguments, you can also use `--config <file>` to point mumble-web-proxy at a toml file which contains them:
```
listen-ws = 64737
server = 'mumbleserver:64738'
```

#### Firewalls or NAT
If your mumble-web-proxy is running behind a firewall or NAT, you need to allocate a range of ports to it which it can use for ICE connection establishment.
```
mumble-web-proxy --listen-ws 64737 --server mumbleserver:64738 --ice-port-min 20000 --ice-port-max 21000
```
For NATs, you additionally need to provide it with its publicly reachable IP address(es):
```
--ice-ipv4 1.2.3.4 --ice-ipv6 1:2:3:4:5::6
```

### License
mumble-web-proxy is available under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

[Mumble]: https://wiki.mumble.info/wiki/Main_Page
[mumble-web]: https://github.com/Johni0702/mumble-web/tree/webrtc
[mumble-web-proxy]: https://github.com/johni0702/mumble-web-proxy

# `PipeBuf` support for websockets

This handles the websocket protocol only, and is independent of the
transport or any other protocol layers below it (such as TLS).  So
this can be combined with other crates such as `pipebuf_mio` or
`pipebuf_rustls` to meet different needs.  It also supports protocol
detection, so that if the data does not appear to be a valid websocket
connection then it can be passed off to another protocol handler such
as HTTP.

### Documentation

See the [crate documentation](http://docs.rs/pipebuf_websocket).

# License

This project is licensed under either the Apache License version 2 or
the MIT license, at your option.  (See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

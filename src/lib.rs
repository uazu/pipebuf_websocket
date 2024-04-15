//! [`PipeBuf`] wrapper for [embedded-websocket]
//!
//! This handles websocket protocol only, independent of the
//! transport.  So this can be combined with `pipebuf_mio` or
//! `pipebuf_rustls` or other crates to meet different needs.
//!
//! This is efficient because [embedded-websocket] exposes a
//! slice-based interface and works between buffers provided by the
//! caller.  So it is ideal to be wrapped by [`PipeBuf`].  Since
//! websocket permits streaming of message data via fragments, a
//! message is here handled as a pipe-buffer allowing the caller to
//! also stream the data if they wish.
//!
//! On the sending side, a "push" is indicated after each message
//! sent.
//!
//! TODO: Support client-side with a `WebsocketClient` wrapper.
//! (Similar to existing code but would need testing.)
//!
//! TODO: Rewrite this as a native PipeBuf-based websocket
//! implementation that for Ping/Pong/Close consumes only whole frames
//! (with limits), to simplify things.  The message content can still
//! be streamed, though.  Also see [Autobahn
//! testsuite](https://github.com/crossbario/autobahn-testsuite).
//!
//! [embedded-websocket]: https://crates.io/crates/embedded-websocket
//! [`PipeBuf`]: https://crates.io/crates/pipebuf

use embedded_websocket as ws;
use httparse::Status;
use pipebuf::{PBufRdWr, PBufWr};
use ws::WebSocketReceiveMessageType as RxMsgType;
use ws::WebSocketSendMessageType as TxMsgType;
use ws::{WebSocketSendMessageType, WebSocketServer, WebSocketSubProtocol};

/// Wraps an [`embedded_websocket::WebSocketServer`]
///
/// [`embedded_websocket::WebSocketServer`]:
/// https://docs.rs/embedded-websocket/0.8.0/embedded_websocket/type.WebSocketServer.html
pub struct WebsocketServer {
    ws: ws::WebSocketServer,
    in_data: Vec<u8>,
    max_msg_len: usize,
    max_aux_len: usize,
}

impl WebsocketServer {
    /// Attempt to interpret the initial data in the given pipe-buffer
    /// stream as websocket HTTP headers and initialise the websocket
    /// stream from them.
    ///
    /// Returns:
    ///
    /// - `Ok(None)` if more data is required
    ///
    /// - `Ok(Some(Self))` if valid HTTP websocket headers were found
    /// and consumed and the websocket is now ready.  A protocol reply
    /// will have been sent back on `pb.wr`.
    ///
    /// - `Err(_)` if the HTTP headers are invalid, or contain invalid
    /// data for a websocket stream.  All the initial data will be
    /// left unconsumed in the pipe buffer in case it can be
    /// interpreted as another protocol
    ///
    /// `subprotocol` argument may be used to specify a subprotocol to
    /// pass back to the client, if required.  See
    /// `embedded_websocket` documentation.
    ///
    /// `max_msg_len` puts a limit on the size of data that will be
    /// allowed in the message buffer before failing the websocket, as
    /// a protection against denial of service attacks.  This is the
    /// limit of how much unread data is allowed in that buffer.  If
    /// the caller streams the data out as it is read, then an
    /// unlimited amount of data may still be received.  In case of
    /// exceeding this limit, `Error::WriteToBufferTooSmall` is
    /// returned.
    ///
    /// `max_aux_len` puts a limit on the size of data associated with
    /// `Ping` and `Close` messages before failing the websocket, as a
    /// protection against denial of service attacks.  In case of
    /// exceeding this limit, `Error::WriteToBufferTooSmall` is
    /// returned.
    ///
    /// `header_cb` is called for each HTTP header line as
    /// `header_cb(field_name, field_value)` once the websocket
    /// connection has been verified in order to allow the caller to
    /// extract whatever details may be required, such as `Origin`.
    pub fn from_http_scan(
        mut pb: PBufRdWr,
        subprotocol: Option<&WebSocketSubProtocol>,
        max_msg_len: usize,
        max_aux_len: usize,
        mut header_cb: impl FnMut(&str, &[u8]),
    ) -> Result<Option<Self>, ws::Error> {
        // `Header` is 2 pointers, so this is 128 bytes (on 64-bit)
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(pb.rd.data()) {
            Err(e) => Err(ws::Error::HttpHeader(e)),
            Ok(Status::Partial) => Ok(None), // Wait for more data
            Ok(Status::Complete(count)) => {
                let headers = request.headers.iter().map(|f| (f.name, f.value));
                match ws::read_http_header(headers)? {
                    None => Err(ws::Error::Unknown), // Actually: not valid WS HTTP headers
                    Some(ws_context) => {
                        let mut ws = WebSocketServer::new_server();
                        let blen = ws.server_accept(
                            &ws_context.sec_websocket_key,
                            subprotocol,
                            pb.wr.space(1024),
                        )?;
                        for h in request.headers.iter() {
                            header_cb(h.name, h.value);
                        }
                        pb.wr.commit(blen);
                        pb.rd.consume(count);
                        Ok(Some(Self::from_wss(ws, max_msg_len, max_aux_len)))
                    }
                }
            }
        }
    }

    /// Attempt to interpret the initial data in the given pipe-buffer
    /// stream as websocket HTTP headers and initialise the websocket
    /// stream from them.
    ///
    /// See [`WebsocketServer::from_http_scan`] for details of
    /// arguments and returns.
    pub fn from_http(
        pb: PBufRdWr,
        subprotocol: Option<&WebSocketSubProtocol>,
        max_msg_len: usize,
        max_aux_len: usize,
    ) -> Result<Option<Self>, ws::Error> {
        Self::from_http_scan(pb, subprotocol, max_msg_len, max_aux_len, |_, _| ())
    }

    /// Create from an already-initialised [`WebSocketServer`]
    ///
    /// `max_msg_len` puts a limit on the size of data that will be
    /// allowed in the message buffer before failing the websocket, as
    /// a protection against denial of service attacks.  This is the
    /// limit of how much unread data is allowed in that buffer.  If
    /// the caller streams the data out as it is read, then an
    /// unlimited amount of data may still be received.  In case of
    /// exceeding this limit, `Error::WriteToBufferTooSmall` is
    /// returned.
    ///
    /// `max_aux_len` puts a limit on the size of data associated with
    /// `Ping` and `Close` messages before failing the websocket, as a
    /// protection against denial of service attacks.  In case of
    /// exceeding this limit, `Error::WriteToBufferTooSmall` is
    /// returned.
    pub fn from_wss(ws: WebSocketServer, max_msg_len: usize, max_aux_len: usize) -> Self {
        Self {
            ws,
            in_data: Vec::new(),
            max_msg_len,
            max_aux_len,
        }
    }

    /// Send an unfragmented websocket text message
    pub fn send_text(&mut self, pb: PBufRdWr, data: &str) -> Result<(), ws::Error> {
        self.send(pb, WebSocketSendMessageType::Text, true, data.as_bytes())
    }

    /// Send an unfragmented websocket binary message
    pub fn send_binary(&mut self, pb: PBufRdWr, data: &[u8]) -> Result<(), ws::Error> {
        self.send(pb, WebSocketSendMessageType::Binary, true, data)
    }

    /// Send an arbitrary websocket message.  This is a wrapper around
    /// [`WebSocketServer::write`].  For an unfragmented message,
    /// `eom` should be `true`.  For a fragmented message, it should
    /// be `true` only for the final fragment.
    pub fn send(
        &mut self,
        mut pb: PBufRdWr,
        msg: WebSocketSendMessageType,
        eom: bool,
        data: &[u8],
    ) -> Result<(), ws::Error> {
        if pb.wr.is_eof() {
            Err(ws::Error::WebSocketNotOpen)
        } else {
            let reserve = 12 + data.len(); // Server frame header is max 10
            let used = self.ws.write(msg, eom, data, pb.wr.space(reserve))?;
            pb.wr.commit(used);
            pb.wr.push();
            Ok(())
        }
    }

    /// Send a reply with the contents of `self.in_data`
    fn send_reply(
        &mut self,
        mut pb: PBufRdWr,
        msg: WebSocketSendMessageType,
    ) -> Result<(), ws::Error> {
        if pb.wr.is_eof() {
            Err(ws::Error::WebSocketNotOpen)
        } else {
            let data = &self.in_data[..];
            let reserve = 12 + data.len(); // Server frame header is max 10
            let used = self.ws.write(msg, true, data, pb.wr.space(reserve))?;
            pb.wr.commit(used);
            Ok(())
        }
    }

    /// Process as much data as possible from the stream.  Whilst
    /// processing, sends back `Pong` and `CloseReply` messages as
    /// necessary according to protocol.  If the stream is closed at a
    /// websocket protocol level, closes the output stream `pb.wr`.
    ///
    /// Received message data is streamed into the `message`
    /// pipe-buffer.  When the end of the message is reached, EOF is
    /// indicated on the pipe-buffer (with state `Closing`).  This
    /// takes care of websocket fragments being used to stream data.
    /// The caller may wait for an EOF and process the entire message,
    /// or else process the data as it comes in (streaming style).
    /// Even partial fragments may result in data being added to the
    /// pipe-buffer, so you can't count on seeing data with the
    /// original fragment boundaries.  `*is_text` will be set
    /// according to the message type: `true` for text, `false` for
    /// binary.  When EOF is indicated on the `message` pipe-buffer,
    /// the caller must process the contents and reset the buffer
    /// (with `PipeBuf::reset()`) before calling this method again, so
    /// that a new message can be read into it.
    ///
    /// Returns `Ok(true)` if there was activity, `Ok(false)` if it is
    /// not possible to advance right now, or `Err(_)` in case of
    /// protocol or limit errors.  After each call check to see
    /// whether a partial or complete message was received.  In case
    /// of EOF on a message, there may be more websocket frames still
    /// to read, so call again.
    pub fn receive(
        &mut self,
        mut pb: PBufRdWr,
        mut message: PBufWr,
        is_text: &mut bool,
    ) -> Result<bool, ws::Error> {
        assert!(!message.is_eof(), "Caller must .reset() buffer after EOF");
        let mut activity = false;
        while !pb.rd.is_empty() {
            // Make sure there is space to read all available data
            let space = message.space(pb.rd.len());
            match self.ws.read(pb.rd.data(), space) {
                Err(ws::Error::ReadFrameIncomplete) => break,
                Err(e) => return Err(e),
                Ok(rr) => {
                    pb.rd.consume(rr.len_from);
                    let to_commit = rr.len_to;
                    activity = true;
                    match rr.message_type {
                        RxMsgType::Text | RxMsgType::Binary => {
                            *is_text = rr.message_type == RxMsgType::Text;
                            message.commit(to_commit);
                            if message.exceeds_limit(self.max_msg_len) {
                                return Err(ws::Error::WriteToBufferTooSmall);
                            }
                            if rr.end_of_message {
                                message.close();
                                break;
                            }
                        }
                        RxMsgType::CloseCompleted => {
                            pb.wr.close();
                        }
                        RxMsgType::CloseMustReply | RxMsgType::Ping | RxMsgType::Pong => {
                            // Due to text/binary message
                            // fragmentation and embedded_websocket's
                            // behaviour regarding partial frames, we
                            // have to build up close/ping/pong data
                            // separately.
                            self.in_data.extend_from_slice(&space[..to_commit]);
                            if self.in_data.len() > self.max_aux_len {
                                return Err(ws::Error::WriteToBufferTooSmall);
                            }
                            if rr.end_of_message {
                                match rr.message_type {
                                    RxMsgType::CloseMustReply => {
                                        self.send_reply(pb.reborrow(), TxMsgType::CloseReply)?;
                                        pb.wr.close();
                                    }
                                    RxMsgType::Ping => {
                                        self.send_reply(pb.reborrow(), TxMsgType::Pong)?;
                                    }
                                    RxMsgType::Pong => (), // Ignore Pongs
                                    _ => (),
                                }
                                self.in_data.clear();
                            }
                        }
                    }
                }
            }
        }
        Ok(activity)
    }
}

use crate::{
    decode_frame_header, decode_frame_preflight,
    frame::{encode_frame, Frame},
    Connections, FrameType, FRAME_HEADER_LEN,
};
use bytes::Bytes;
use iroh::endpoint::{Connection, ConnectionType, RecvStream, SendStream};
use kitsune2_api::{K2Error, K2Result, Timestamp, TxImpHnd, Url};
use n0_watcher::Watcher;
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tokio::{sync::MutexGuard, task::AbortHandle};
use tracing::{debug, error, info, trace, warn};

pub(super) struct ConnectionContext {
    handler: Arc<TxImpHnd>,
    connection: Arc<Connection>,
    connection_reader_abort_handle: Mutex<Option<AbortHandle>>,
    send_stream: tokio::sync::Mutex<Option<SendStream>>,
    remote_url: RwLock<Option<Url>>,
    preflight_sent: AtomicBool,
    preflight_received: AtomicBool,
    send_message_count: AtomicU64,
    send_bytes: AtomicU64,
    recv_message_count: AtomicU64,
    recv_bytes: AtomicU64,
    opened_at_s: u64,
    connection_type_watcher: Mutex<Option<n0_watcher::Direct<ConnectionType>>>,
    max_frame_bytes: usize,
}

impl fmt::Debug for ConnectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionContext").finish()
    }
}

pub(super) struct ConnectionContextParams {
    pub handler: Arc<TxImpHnd>,
    pub connection: Arc<Connection>,
    pub remote_url: Option<Url>,
    pub preflight_sent: bool,
    pub opened_at_s: u64,
    pub connection_type_watcher: Option<n0_watcher::Direct<ConnectionType>>,
    pub connections: Connections,
    pub local_url: Arc<RwLock<Option<Url>>>,
    pub max_frame_bytes: usize,
}

impl ConnectionContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(params: ConnectionContextParams) -> Arc<Self> {
        info!(
            remote_id = ?params.connection.remote_id(),
            remote_url = ?params.remote_url,
            preflight_sent = params.preflight_sent,
            max_frame_bytes = params.max_frame_bytes,
            "ConnectionContext::new creating new context"
        );

        let ctx = Arc::new(Self {
            handler: params.handler,
            connection: params.connection,
            connection_reader_abort_handle: Mutex::new(None),
            send_stream: tokio::sync::Mutex::new(None),
            remote_url: RwLock::new(params.remote_url),
            preflight_sent: AtomicBool::new(params.preflight_sent),
            preflight_received: AtomicBool::new(false),
            send_message_count: AtomicU64::new(0),
            send_bytes: AtomicU64::new(0),
            recv_message_count: AtomicU64::new(0),
            recv_bytes: AtomicU64::new(0),
            opened_at_s: params.opened_at_s,
            connection_type_watcher: Mutex::new(params.connection_type_watcher),
            max_frame_bytes: params.max_frame_bytes,
        });

        // Spawn connection reader to listen for incoming connections on the
        // new connection.
        debug!(
            remote_id = ?ctx.connection.remote_id(),
            "ConnectionContext::new spawning connection reader task"
        );
        let connection_reader_abort_handle = Self::spawn_connection_reader(
            ctx.clone(),
            params.connections,
            params.local_url,
        );
        *ctx.connection_reader_abort_handle.lock().expect("poisoned") =
            Some(connection_reader_abort_handle);

        debug!(
            remote_id = ?ctx.connection.remote_id(),
            "ConnectionContext::new completed"
        );
        ctx
    }

    pub async fn send_preflight_frame(
        &self,
        url: Url,
        preflight_bytes: Bytes,
    ) -> K2Result<()> {
        debug!(
            local_url = ?url,
            preflight_bytes_len = preflight_bytes.len(),
            remote_id = ?self.connection.remote_id(),
            "send_preflight_frame: encoding preflight frame"
        );
        let frame = encode_frame(
            Frame::Preflight((url.clone(), preflight_bytes)),
            self.max_frame_bytes,
        )?;
        debug!(
            frame_len = frame.len(),
            "send_preflight_frame: preflight frame encoded"
        );

        trace!("send_preflight_frame: ensuring send stream exists");
        let mut stream_lock = self.ensure_send_stream().await?;
        let stream = stream_lock.as_mut().expect("stream must exist");

        info!(
            local_url = ?url,
            frame_len = frame.len(),
            remote_id = ?self.connection.remote_id(),
            "send_preflight_frame: sending preflight frame"
        );
        trace!(frame = ?frame, "send_preflight_frame: frame bytes");
        if let Err(err) = stream.write_all(&frame).await {
            error!(
                ?err,
                local_url = ?url,
                remote_id = ?self.connection.remote_id(),
                "send_preflight_frame: failed to write preflight frame to stream"
            );
            *stream_lock = None;
            return Err(K2Error::other_src(
                "failed to send preflight frame",
                err,
            ));
        }

        debug!(
            local_url = ?url,
            remote_id = ?self.connection.remote_id(),
            "send_preflight_frame: preflight frame sent successfully"
        );
        Ok(())
    }

    pub async fn send_data_frame(&self, data: Bytes) -> K2Result<()> {
        let data_len = data.len() as u64;
        debug!(
            data_len,
            remote_url = ?self.remote_url(),
            remote_id = ?self.connection.remote_id(),
            "send_data_frame: encoding data frame"
        );
        let frame = encode_frame(Frame::Data(data), self.max_frame_bytes)?;
        debug!(
            frame_len = frame.len(),
            "send_data_frame: data frame encoded"
        );

        trace!("send_data_frame: ensuring send stream exists");
        let mut stream_lock = self.ensure_send_stream().await?;
        let stream = stream_lock.as_mut().expect("stream must exist");

        trace!(
            frame_len = frame.len(),
            remote_url = ?self.remote_url(),
            "send_data_frame: writing frame to stream"
        );
        if let Err(err) = stream.write_all(&frame).await {
            error!(
                ?err,
                data_len,
                remote_url = ?self.remote_url(),
                remote_id = ?self.connection.remote_id(),
                "send_data_frame: failed to write data frame to stream"
            );
            *stream_lock = None;
            return Err(K2Error::other_src("failed to send data frame", err));
        }

        drop(stream_lock);

        // Update stats
        self.increment_send_message_count();
        self.increment_send_bytes(data_len);

        debug!(
            data_len,
            remote_url = ?self.remote_url(),
            total_messages_sent = self.get_send_message_count(),
            total_bytes_sent = self.get_send_bytes(),
            "send_data_frame: data frame sent successfully"
        );

        Ok(())
    }

    pub fn remote_url(&self) -> Option<Url> {
        self.remote_url.read().expect("poisoned").clone()
    }

    pub fn get_send_message_count(&self) -> u64 {
        self.send_message_count.load(Ordering::SeqCst)
    }

    pub fn get_send_bytes(&self) -> u64 {
        self.send_bytes.load(Ordering::SeqCst)
    }

    pub fn get_recv_message_count(&self) -> u64 {
        self.recv_message_count.load(Ordering::SeqCst)
    }

    pub fn get_recv_bytes(&self) -> u64 {
        self.recv_bytes.load(Ordering::SeqCst)
    }

    pub fn get_opened_at_s(&self) -> u64 {
        self.opened_at_s
    }

    pub fn get_connection_type(&self) -> ConnectionType {
        let mut lock = self.connection_type_watcher.lock().expect("poisoned");
        match lock.take() {
            Some(mut watcher) => {
                let connection_type = watcher.get();
                *lock = Some(watcher);
                connection_type
            }
            None => ConnectionType::None,
        }
    }

    pub fn abort_tasks(&self) {
        if let Some(abort_handle) = self
            .connection_reader_abort_handle
            .lock()
            .expect("poisoned")
            .take()
        {
            abort_handle.abort();
        }
    }

    pub fn disconnect(&self, reason: String) {
        info!(
            reason = %reason,
            remote_url = ?self.remote_url(),
            remote_id = ?self.connection.remote_id(),
            total_messages_sent = self.get_send_message_count(),
            total_bytes_sent = self.get_send_bytes(),
            total_messages_recv = self.get_recv_message_count(),
            total_bytes_recv = self.get_recv_bytes(),
            "disconnect: closing connection"
        );
        self.connection.close(0u8.into(), reason.as_bytes());
        if let Some(peer) = self.remote_url() {
            debug!(peer = ?peer, "disconnect: notifying handler of peer disconnect");
            self.handler.peer_disconnect(peer, Some(reason));
        } else {
            debug!("disconnect: no remote URL set, skipping handler notification");
        }
    }

    // Spawns an asynchronous task to continuously read and handle incoming uni-directional
    // streams from an iroh connection. There is only one stream at a time incoming from a
    // remote. It's read from until the connection is closed or an error occurs.
    //
    // Errors when receiving the preflight frame lead to a break of the loop accepting
    // incoming streams. The preflight must succeed for data frames to be accepted. The
    // connection cannot recover from a failed preflight, and a new connection must be
    // established.
    //
    // # Parameters
    // - `ctx`: The connection context containing handler and remote URL state.
    // - `connections`: Shared map of peer URLs to their connection contexts, updated when
    //   the preflight succeeds.
    // - `local_url`: The local URL for this endpoint, used to respond to preflight messages.
    fn spawn_connection_reader(
        ctx: Arc<Self>,
        connections: Connections,
        local_url: Arc<RwLock<Option<Url>>>,
    ) -> AbortHandle {
        let remote_id = ctx.connection.remote_id();
        info!(
            remote_id = ?remote_id,
            "spawn_connection_reader: starting connection reader task"
        );
        tokio::spawn(async move {
            debug!(
                remote_id = ?ctx.connection.remote_id(),
                "spawn_connection_reader: entering main loop"
            );
            let err = loop {
                // Main loop to accept incoming unidirectional streams from the remote peer.
                trace!(
                    remote_id = ?ctx.connection.remote_id(),
                    "spawn_connection_reader: waiting for incoming stream..."
                );
                match ctx.connection.accept_uni().await {
                    Ok(stream) => {
                        info!(
                            remote_id = ?ctx.connection.remote_id(),
                            stream_id = ?stream.id(),
                            "spawn_connection_reader: accepted incoming uni-directional stream"
                        );
                        let connections = connections.clone();
                        let local_url = local_url.clone();
                        // Read frames from the stream. If an error is returned, it means the
                        // preflight couldn't be received. The connection must be closed in that
                        // case, because a successful preflight is the prerequisite for establishing
                        // a connection.
                        //
                        // Errors while receiving data frames from the stream indicate a problem
                        // with the stream and lead to closing it. An `Ok` value is returned, so
                        // that the connection is kept open and the next incoming stream is
                        // awaited.
                        debug!(
                            remote_id = ?ctx.connection.remote_id(),
                            "spawn_connection_reader: handling incoming stream"
                        );
                        if let Err(err) = Self::handle_incoming_stream(
                            ctx.clone(),
                            stream,
                            connections.clone(),
                            local_url,
                        )
                        .await
                        {
                            error!(
                                ?err,
                                remote_id = ?ctx.connection.remote_id(),
                                remote_url = ?ctx.remote_url(),
                                "spawn_connection_reader: stream handling failed, breaking loop"
                            );
                            break err.to_string();
                        }
                        debug!(
                            remote_id = ?ctx.connection.remote_id(),
                            "spawn_connection_reader: stream handled successfully, waiting for next stream"
                        );
                    }
                    Err(err) => {
                        error!(
                            ?err,
                            remote_id = ?ctx.connection.remote_id(),
                            remote_url = ?ctx.remote_url(),
                            "spawn_connection_reader: connection closed by remote or error accepting stream"
                        );
                        break err.to_string();
                    }
                }
            };

            // An error has occurred, either while accepting incoming streams
            // (most likely connection closed) or while reading the preflight
            // from a stream. The protocol can not recover from this error
            // and the connection must be closed. The remote is marked as
            // unresponsive.
            warn!(
                error = %err,
                remote_id = ?ctx.connection.remote_id(),
                remote_url = ?ctx.remote_url(),
                "spawn_connection_reader: exited main loop due to error"
            );
            if let Some(remote_url) = ctx.remote_url() {
                debug!(
                    remote_url = ?remote_url,
                    "spawn_connection_reader: removing connection from map"
                );
                connections
                    .write()
                    .expect("poisoned")
                    .remove(&remote_url);
                info!(
                    remote_url = ?remote_url,
                    "spawn_connection_reader: setting peer unresponsive"
                );
                if let Err(err) = ctx.handler.set_unresponsive(remote_url.clone(), Timestamp::now()).await{
                    warn!(?err, ?remote_url, "spawn_connection_reader: failed to set peer unresponsive");
                }
            } else {
                debug!("spawn_connection_reader: no remote URL set, skipping unresponsive notification");
            }
            ctx.disconnect(err);
        }).abort_handle()
    }

    // Handle frames from an incoming stream.
    //
    // By convention, the first frame on a new connection is the
    // preflight. After the preflight has been received, the flag is
    // updated in the context.
    //
    // If the preflight has not been received yet, read the preflight
    // from the stream. Time out if the preflight isn't received and
    // return an error to close the stream.
    //
    // The protocol can't recover from a failed preflight frame.
    // The stream must be closed with an error, which causes the
    // connection to be closed. A new connection must be established
    // and the preflight has to be sent again.
    //
    // Once the preflight frame has been successfully received, data
    // frames can be read from the stream. No other frames are allowed
    // after the preflight.
    //
    // Data frames will be read from the stream until an error of any
    // kind occurs. Errors during data frame header or data reception
    // or decoding will close the stream, but not the connection.
    // The connection reader will await the next incoming stream.
    async fn handle_incoming_stream(
        ctx: Arc<Self>,
        mut recv_stream: RecvStream,
        connections: Connections,
        local_url: Arc<RwLock<Option<Url>>>,
    ) -> K2Result<()> {
        debug!(
            remote_id = ?ctx.connection.remote_id(),
            stream_id = ?recv_stream.id(),
            preflight_received = ctx.preflight_received(),
            "handle_incoming_stream: starting stream handling"
        );

        if !ctx.preflight_received() {
            debug!(
                remote_id = ?ctx.connection.remote_id(),
                "handle_incoming_stream: preflight not yet received, waiting for preflight frame (10s timeout)"
            );
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                trace!("handle_incoming_stream: reading preflight frame from stream");
                let (remote_url, preflight_bytes) = read_preflight_frame_from_stream(&mut recv_stream,ctx.max_frame_bytes).await?;
                debug!(
                    remote_url = ?remote_url,
                    preflight_bytes_len = preflight_bytes.len(),
                    "handle_incoming_stream: preflight frame read successfully"
                );

                ctx.set_remote_url(remote_url.clone());
                debug!(
                    remote_url = ?remote_url,
                    "handle_incoming_stream: forwarding preflight bytes to handler"
                );
                ctx.handler
                    .recv_data(remote_url.clone(), preflight_bytes)
                    .await?;
                ctx.set_preflight_received();
                info!(
                    remote = ?remote_url.peer_id(),
                    remote_url = ?remote_url,
                    "handle_incoming_stream: preflight received and processed successfully"
                );

                // If the preflight has not been sent yet, it must be the first message
                // sent back to the remote.
                if !ctx.preflight_sent() {
                    debug!(
                        remote_id = ?ctx.connection.remote_id(),
                        "handle_incoming_stream: preflight not yet sent, preparing return preflight"
                    );
                    let maybe_local_url =
                        local_url.read().expect("poisoned").clone();
                    if let Some(local_url) = maybe_local_url {
                        debug!(
                            local_url = ?local_url,
                            remote_url = ?remote_url,
                            "handle_incoming_stream: requesting preflight bytes from handler"
                        );
                        let return_preflight =
                            ctx.handler.peer_connect(remote_url.clone()).await?;
                        debug!(
                            return_preflight_len = return_preflight.len(),
                            "handle_incoming_stream: sending return preflight frame"
                        );
                        ctx.send_preflight_frame(
                            local_url.clone(),
                            return_preflight,
                        )
                        .await?;
                        info!(
                            peer = ?ctx.connection.remote_id(),
                            local_url = ?local_url,
                            remote_url = ?remote_url,
                            "handle_incoming_stream: return preflight sent successfully"
                        );
                        ctx.set_preflight_sent();
                    } else {
                        warn!(
                            peer = ?ctx.connection.remote_id(),
                            "handle_incoming_stream: received preflight but cannot return - own URL is unknown"
                        );
                        return Err(K2Error::other("Connection received before home relay URL is known"));
                    }
                } else {
                    debug!(
                        remote_id = ?ctx.connection.remote_id(),
                        "handle_incoming_stream: preflight already sent (outgoing connection)"
                    );
                }

                Ok(remote_url)
            })
        .await
        .map_err(|err| {
            error!(
                ?err,
                remote_id = ?ctx.connection.remote_id(),
                "handle_incoming_stream: timed out waiting for preflight"
            );
            K2Error::other_src("timed out waiting for preflight", err)
        });
            match result {
                Ok(Ok(remote_url)) => {
                    debug!(
                        remote_url = ?remote_url,
                        "handle_incoming_stream: adding connection to connections map"
                    );
                    connections
                        .write()
                        .expect("poisoned")
                        .insert(remote_url.clone(), ctx.clone());
                    info!(
                        remote_url = ?remote_url,
                        "handle_incoming_stream: connection established and added to map"
                    );
                }
                Ok(Err(err)) | Err(err) => {
                    error!(
                        ?err,
                        remote_id = ?ctx.connection.remote_id(),
                        "handle_incoming_stream: failed to receive/process preflight frame"
                    );
                    return Err(err);
                }
            }
        } else {
            debug!(
                remote_id = ?ctx.connection.remote_id(),
                "handle_incoming_stream: preflight already received, proceeding to data frames"
            );
        }

        // Keep reading data frames from the stream until it is closed.
        debug!(
            remote_id = ?ctx.connection.remote_id(),
            remote_url = ?ctx.remote_url(),
            "handle_incoming_stream: entering data frame read loop"
        );
        let mut frame_count = 0u64;
        loop {
            trace!(
                remote_id = ?ctx.connection.remote_id(),
                frame_count,
                "handle_incoming_stream: waiting for next data frame..."
            );
            let (data, data_len) = match read_data_frame_from_stream(
                &mut recv_stream,
                ctx.max_frame_bytes,
            )
            .await
            {
                Ok(data) => {
                    frame_count += 1;
                    debug!(
                        data_len = data.1,
                        frame_count,
                        remote_url = ?ctx.remote_url(),
                        "handle_incoming_stream: data frame received"
                    );
                    data
                }
                Err(err) => {
                    if frame_count == 0 {
                        warn!(
                            ?err,
                            remote_url = ?ctx.remote_url(),
                            "handle_incoming_stream: error receiving first data frame (stream may have been closed)"
                        );
                    } else {
                        debug!(
                            ?err,
                            frame_count,
                            remote_url = ?ctx.remote_url(),
                            total_recv_messages = ctx.get_recv_message_count(),
                            total_recv_bytes = ctx.get_recv_bytes(),
                            "handle_incoming_stream: stream ended (error reading data frame)"
                        );
                    }
                    // Frame header could not be read or decoded, wrong frame type
                    // or data frame data could not be read.
                    // Break the loop to close the stream, but not the connection.
                    break;
                }
            };

            // Handle data frame: forward data to handler if remote URL is set.
            let peer = ctx.remote_url().ok_or_else(|| {
                error!("handle_incoming_stream: received data before preflight (should not happen)");
                K2Error::other("received data before preflight")
            })?;
            trace!(
                peer = ?peer.peer_id(),
                data_len,
                "handle_incoming_stream: forwarding data to handler"
            );
            if let Err(err) = ctx
                .handler
                .recv_data(peer.clone(), Bytes::copy_from_slice(&data))
                .await
            {
                error!(
                    ?err,
                    remote = ?peer.peer_id(),
                    data_len,
                    "handle_incoming_stream: error forwarding data to handler"
                );
            } else {
                trace!(
                    remote = ?peer.peer_id(),
                    data_len,
                    "handle_incoming_stream: data forwarded to handler successfully"
                );
            };

            ctx.increment_recv_message_count();
            ctx.increment_recv_bytes(data_len as u64);
        }

        debug!(
            remote_url = ?ctx.remote_url(),
            frame_count,
            total_recv_messages = ctx.get_recv_message_count(),
            total_recv_bytes = ctx.get_recv_bytes(),
            "handle_incoming_stream: exiting stream handling"
        );
        Ok(())
    }

    async fn ensure_send_stream(
        &'_ self,
    ) -> K2Result<MutexGuard<'_, Option<SendStream>>> {
        // Atomically open a new stream if none is present.
        trace!(
            remote_id = ?self.connection.remote_id(),
            "ensure_send_stream: acquiring send stream lock"
        );
        let mut stream_lock = self.send_stream.lock().await;
        if stream_lock.is_none() {
            debug!(
                remote_id = ?self.connection.remote_id(),
                remote_url = ?self.remote_url(),
                "ensure_send_stream: no stream exists, opening new uni-directional stream"
            );
            let stream = self.connection.open_uni().await.map_err(|err| {
                error!(
                    ?err,
                    remote_id = ?self.connection.remote_id(),
                    "ensure_send_stream: failed to open uni-directional stream"
                );
                K2Error::other_src("failed to open uni-directional stream", err)
            })?;
            info!(
                stream_id = ?stream.id(),
                remote_id = ?self.connection.remote_id(),
                remote_url = ?self.remote_url(),
                "ensure_send_stream: new uni-directional stream opened successfully"
            );
            *stream_lock = Some(stream);
        } else {
            trace!(
                remote_id = ?self.connection.remote_id(),
                "ensure_send_stream: reusing existing stream"
            );
        }
        Ok(stream_lock)
    }

    fn set_remote_url(&self, peer: Url) {
        *self.remote_url.write().expect("poisoned") = Some(peer);
    }

    fn preflight_sent(&self) -> bool {
        self.preflight_sent.load(Ordering::SeqCst)
    }

    fn set_preflight_sent(&self) {
        self.preflight_sent.store(true, Ordering::SeqCst)
    }

    fn preflight_received(&self) -> bool {
        self.preflight_received.load(Ordering::SeqCst)
    }

    fn set_preflight_received(&self) {
        self.preflight_received.store(true, Ordering::SeqCst);
    }

    fn increment_send_message_count(&self) {
        self.send_message_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_send_bytes(&self, len: u64) {
        self.send_bytes.fetch_add(len, Ordering::SeqCst);
    }

    fn increment_recv_message_count(&self) {
        self.recv_message_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_recv_bytes(&self, len: u64) {
        self.recv_bytes.fetch_add(len, Ordering::SeqCst);
    }
}

async fn read_preflight_frame_from_stream(
    recv_stream: &mut RecvStream,
    max_frame_bytes: usize,
) -> K2Result<(Url, Bytes)> {
    trace!(
        stream_id = ?recv_stream.id(),
        max_frame_bytes,
        "read_preflight_frame_from_stream: reading preflight header"
    );
    let mut header_bytes = [0u8; FRAME_HEADER_LEN];
    recv_stream
        .read_exact(&mut header_bytes)
        .await
        .map_err(|err| {
            error!(
                ?err,
                stream_id = ?recv_stream.id(),
                "read_preflight_frame_from_stream: failed to read preflight header"
            );
            K2Error::other_src("preflight header read failed", err)
        })?;
    trace!(
        header_bytes = ?header_bytes,
        "read_preflight_frame_from_stream: header bytes read"
    );
    let (frame_type, data_len) =
        decode_frame_header(&header_bytes, max_frame_bytes)?;
    debug!(
        ?frame_type,
        data_len,
        stream_id = ?recv_stream.id(),
        "read_preflight_frame_from_stream: decoded preflight frame header"
    );
    if frame_type == FrameType::Data {
        error!(
            stream_id = ?recv_stream.id(),
            "read_preflight_frame_from_stream: expected preflight frame but received data frame"
        );
        return Err(K2Error::other(
            "preflight frame expected, received data frame",
        ));
    };
    trace!(
        data_len,
        "read_preflight_frame_from_stream: reading preflight data"
    );
    let mut preflight_bytes = vec![0u8; data_len];
    recv_stream
        .read_exact(&mut preflight_bytes)
        .await
        .map_err(|err| {
            error!(
                ?err,
                data_len,
                "read_preflight_frame_from_stream: failed to read preflight data"
            );
            K2Error::other_src("preflight data read failed", err)
        })?;
    trace!(
        preflight_bytes_len = preflight_bytes.len(),
        "read_preflight_frame_from_stream: preflight data read, decoding"
    );
    let (remote_url, preflight_bytes) =
        decode_frame_preflight(&preflight_bytes)?;
    debug!(
        remote = ?remote_url.peer_id(),
        remote_url = %remote_url,
        preflight_payload_len = preflight_bytes.len(),
        "read_preflight_frame_from_stream: preflight frame decoded successfully"
    );
    Ok((remote_url, preflight_bytes))
}

async fn read_data_frame_from_stream(
    recv_stream: &mut RecvStream,
    max_frame_bytes: usize,
) -> K2Result<(Vec<u8>, usize)> {
    // Read data frame header
    trace!(
        stream_id = ?recv_stream.id(),
        "read_data_frame_from_stream: reading data frame header"
    );
    let mut header = [0u8; FRAME_HEADER_LEN];
    recv_stream.read_exact(&mut header).await.map_err(|err| {
        // This is often just the stream being closed normally, so use debug level
        debug!(
            ?err,
            stream_id = ?recv_stream.id(),
            "read_data_frame_from_stream: error reading data frame header (may be normal stream close)"
        );
        K2Error::other_src("error reading data frame header", err)
    })?;
    trace!(
        header = ?header,
        "read_data_frame_from_stream: header bytes read"
    );
    let (frame_type, data_len) = decode_frame_header(&header, max_frame_bytes)
        .map_err(|err| {
            error!(
                ?err,
                header = ?header,
                "read_data_frame_from_stream: failed to decode frame header"
            );
            K2Error::other_src("failed to decode iroh frame header", err)
        })?;
    trace!(
        ?frame_type,
        data_len,
        "read_data_frame_from_stream: decoded frame header"
    );
    if frame_type == FrameType::Preflight {
        error!(
            stream_id = ?recv_stream.id(),
            "read_data_frame_from_stream: expected data frame but received preflight frame"
        );
        return Err(K2Error::other(
            "data frame expected, received preflight frame",
        ));
    }
    // Read data frame data
    trace!(
        data_len,
        "read_data_frame_from_stream: reading data frame payload"
    );
    let mut data = vec![0u8; data_len];
    recv_stream.read_exact(&mut data).await.map_err(|err| {
        error!(
            ?err,
            data_len,
            stream_id = ?recv_stream.id(),
            "read_data_frame_from_stream: error reading data frame payload"
        );
        K2Error::other_src("error reading data frame data", err)
    })?;
    trace!(
        data_len,
        "read_data_frame_from_stream: data frame read successfully"
    );
    Ok((data, data_len))
}

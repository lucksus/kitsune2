use bytes::Bytes;
use kitsune2_api::{K2Error, K2Result, Url};
use tracing::{debug, error, trace};

pub(super) const FRAME_HEADER_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum FrameType {
    // Preflight consists of peer URL and preflight
    Preflight = 0,
    Data = 1,
}

impl TryFrom<u8> for FrameType {
    type Error = K2Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FrameType::Preflight),
            1 => Ok(FrameType::Data),
            _ => {
                Err(K2Error::other(format!("unknown iroh frame type: {value}")))
            }
        }
    }
}

#[derive(Debug)]
pub(super) enum Frame {
    Preflight((Url, Bytes)),
    Data(Bytes),
}

/// Encodes a frame header for the given frame type and payload length.
///
/// The frame format consists of:
/// - 1 byte for frame type (0 for Preflight, 1 for Data)
/// - 4 bytes for payload length (big-endian u32)
///
/// Returns an error if the total frame size exceeds `max_frame_bytes`.
fn encode_frame_header(
    ty: FrameType,
    data_len: usize,
    max_frame_bytes: usize,
) -> K2Result<Vec<u8>> {
    trace!(
        frame_type = ?ty,
        data_len,
        max_frame_bytes,
        total_size = data_len + FRAME_HEADER_LEN,
        "encode_frame_header: encoding header"
    );
    if data_len + FRAME_HEADER_LEN > max_frame_bytes {
        error!(
            data_len,
            max_frame_bytes,
            total_size = data_len + FRAME_HEADER_LEN,
            "encode_frame_header: frame too large"
        );
        return Err(K2Error::other("frame too large"));
    }
    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    header.push(ty as u8);
    header.extend_from_slice(&(data_len as u32).to_be_bytes());
    trace!(
        header = ?header,
        "encode_frame_header: header encoded"
    );
    Ok(header)
}

/// Encodes a given frame.
///
/// The frame format consists of:
/// - 1 byte for frame type (0 for Preflight, 1 for Data)
/// - 4 bytes for payload length (big-endian u32)
/// - The payload data following the header
///
/// Payload data can be either the preflight or data.
/// The preflight consists of:
/// - 4 bytes for the URL length
/// - The URL
/// - The preflight bytes
///
/// Data is just the bytes of the data.
///
/// # Errors
///
/// Returns an error when `max_frame_bytes` are exceeded.
pub(super) fn encode_frame(
    frame: Frame,
    max_frame_bytes: usize,
) -> K2Result<Bytes> {
    match frame {
        Frame::Preflight((url, preflight)) => {
            debug!(
                url = %url,
                preflight_len = preflight.len(),
                max_frame_bytes,
                "encode_frame: encoding preflight frame"
            );
            let url_bytes = Bytes::copy_from_slice(url.as_str().as_bytes());
            let mut data = vec![];
            data.extend_from_slice(&(url_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(&url_bytes);
            data.extend_from_slice(&preflight);
            trace!(
                url_bytes_len = url_bytes.len(),
                total_data_len = data.len(),
                "encode_frame: preflight data assembled"
            );
            let mut frame = encode_frame_header(
                FrameType::Preflight,
                data.len(),
                max_frame_bytes,
            )?;
            frame.extend(&data);
            debug!(
                total_frame_len = frame.len(),
                "encode_frame: preflight frame encoded successfully"
            );
            Ok(Bytes::copy_from_slice(&frame))
        }
        Frame::Data(data) => {
            trace!(
                data_len = data.len(),
                max_frame_bytes,
                "encode_frame: encoding data frame"
            );
            let mut frame = encode_frame_header(
                FrameType::Data,
                data.len(),
                max_frame_bytes,
            )?;
            frame.extend(&data);
            trace!(
                total_frame_len = frame.len(),
                "encode_frame: data frame encoded successfully"
            );
            Ok(Bytes::copy_from_slice(&frame))
        }
    }
}

/// Decodes a frame header from raw byte data into a frame type and data length.
///
/// The frame header consists of:
/// - 1 byte for frame type (0 for Preflight, 1 for Data)
/// - 4 bytes for data length (big-endian u32)
///
/// The frame type and data length are returned as separate values.
///
/// # Errors
///
/// Returns an error if the data is shorter than the header, contains an invalid
/// frame type, or the data length plus frame header length exceed the `max_frame_bytes`.
pub(super) fn decode_frame_header(
    data: &[u8],
    max_frame_bytes: usize,
) -> K2Result<(FrameType, usize)> {
    trace!(
        data_len = data.len(),
        max_frame_bytes,
        "decode_frame_header: decoding header"
    );
    if data.len() < FRAME_HEADER_LEN {
        error!(
            data_len = data.len(),
            expected = FRAME_HEADER_LEN,
            "decode_frame_header: frame shorter than header"
        );
        return Err(K2Error::other(
            "iroh frame shorter than header".to_string(),
        ));
    }
    // Parse frame type from header byte.
    let frame_type_byte = data[0];
    let frame_type = FrameType::try_from(frame_type_byte).map_err(|err| {
        error!(
            frame_type_byte,
            "decode_frame_header: invalid frame type byte"
        );
        err
    })?;
    // Extract data length from next 4 bytes.
    let data_len =
        u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    trace!(
        ?frame_type,
        data_len,
        total_frame_size = data_len + FRAME_HEADER_LEN,
        "decode_frame_header: parsed header values"
    );
    if data_len + FRAME_HEADER_LEN > max_frame_bytes {
        error!(
            data_len,
            max_frame_bytes,
            total_frame_size = data_len + FRAME_HEADER_LEN,
            "decode_frame_header: frame too large"
        );
        return Err(K2Error::other("iroh frame too large".to_string()));
    }
    debug!(
        ?frame_type,
        data_len,
        "decode_frame_header: header decoded successfully"
    );
    Ok((frame_type, data_len))
}

/// Decodes a preflight frame from raw byte data.
///
/// The preflight consists of:
/// - 4 bytes for the URL length
/// - The URL
/// - The preflight bytes
///
/// The URL and the preflight bytes are returned as separate values.
///
/// # Errors
///
/// Returns an error if the data is shorter than 4 bytes for the URL length, or shorter
/// than 4 bytes for the URL length plus the bytes of the URL, and if the URL has an
/// invalid format.
pub(super) fn decode_frame_preflight(data: &[u8]) -> K2Result<(Url, Bytes)> {
    trace!(
        data_len = data.len(),
        "decode_frame_preflight: decoding preflight data"
    );
    // If there are less than 4 bytes that indicate the URL length, return an error.
    if data.len() < 4 {
        error!(
            data_len = data.len(),
            "decode_frame_preflight: data too short for URL length field"
        );
        return Err(K2Error::other("preflight data too short for URL length"));
    }
    // The first 4 bytes of the data are the URL length...
    let url_len =
        u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    trace!(
        url_len,
        remaining_data = data.len() - 4,
        "decode_frame_preflight: parsed URL length"
    );
    // If the data length is shorter than 4 bytes for the URL length plus the bytes
    // for the URL, return an error.
    if data.len() < 4 + url_len {
        error!(
            data_len = data.len(),
            url_len,
            required = 4 + url_len,
            "decode_frame_preflight: data too short for URL"
        );
        return Err(K2Error::other("preflight data too short for actual URL"));
    }
    // ...followed by the URL
    let url_str = std::str::from_utf8(&data[4..4 + url_len])
        .map_err(|err| {
            error!(
                ?err,
                "decode_frame_preflight: URL bytes are not valid UTF-8"
            );
            K2Error::other_src("invalid peer url", err)
        })?;
    trace!(
        url_str,
        "decode_frame_preflight: parsed URL string"
    );
    let url = Url::from_str(url_str)?;
    // The preflight takes up the rest of the data,
    // after the URL length and the URL.
    let preflight_bytes = Bytes::copy_from_slice(&data[4 + url_len..]);
    debug!(
        url = %url,
        peer_id = ?url.peer_id(),
        preflight_bytes_len = preflight_bytes.len(),
        "decode_frame_preflight: preflight decoded successfully"
    );
    Ok((url, preflight_bytes))
}

use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use kitsune2_api::{K2Error, K2Result, Url};
use std::str::FromStr;
use tracing::{debug, error, trace};

pub(super) fn get_url_with_first_relay(
    endpoint_addr: &EndpointAddr,
) -> Option<Url> {
    trace!(
        endpoint_id = ?endpoint_addr.id,
        relay_count = endpoint_addr.relay_urls().count(),
        "get_url_with_first_relay: searching for relay URL"
    );
    let result = endpoint_addr.relay_urls().find_map(
        |relay_url| {
            trace!(
                relay_url = %relay_url,
                "get_url_with_first_relay: trying relay URL"
            );
            match canonicalize_relay_url(relay_url, endpoint_addr.id) {
                Ok(url) => {
                    debug!(
                        url = %url,
                        relay_url = %relay_url,
                        "get_url_with_first_relay: successfully canonicalized relay URL"
                    );
                    Some(url)
                }
                Err(err) => {
                    error!(
                        relay_url = %relay_url,
                        ?err,
                        "get_url_with_first_relay: could not canonicalize RelayUrl"
                    );
                    None
                }
            }
        },
    );
    if result.is_none() {
        debug!(
            endpoint_id = ?endpoint_addr.id,
            "get_url_with_first_relay: no valid relay URL found"
        );
    }
    result
}

pub(super) fn canonicalize_relay_url(
    relay_url: &RelayUrl,
    endpoint_id: EndpointId,
) -> K2Result<Url> {
    trace!(
        relay_url = %relay_url,
        endpoint_id = ?endpoint_id,
        "canonicalize_relay_url: canonicalizing relay URL"
    );
    let canonical_relay_url = if relay_url.port().is_none() {
        trace!("canonicalize_relay_url: relay URL has no explicit port, using default");
        let relay_host = relay_url
            .host()
            .ok_or_else(|| {
                error!(relay_url = %relay_url, "canonicalize_relay_url: relay URL has no host");
                K2Error::other("relay url must have host")
            })?;
        let relay_host = match relay_host {
            ::url::Host::Ipv6(addr) => format!("[{addr}]"),
            other => other.to_string(),
        };
        let relay_port =
            relay_url.port_or_known_default().ok_or_else(|| {
                error!(
                    relay_url = %relay_url,
                    "canonicalize_relay_url: relay URL has no known default port"
                );
                K2Error::other("relay url must have known default port")
            })?;
        trace!(
            relay_host,
            relay_port,
            scheme = relay_url.scheme(),
            "canonicalize_relay_url: building canonical URL"
        );
        format!(
            "{}://{}:{}/{}",
            relay_url.scheme(),
            relay_host,
            relay_port,
            endpoint_id
        )
    } else {
        trace!(
            port = ?relay_url.port(),
            "canonicalize_relay_url: using explicit port from relay URL"
        );
        format!("{relay_url}{endpoint_id}")
    };
    debug!(
        canonical_relay_url,
        "canonicalize_relay_url: canonical URL string created"
    );
    Url::from_str(canonical_relay_url)
}

pub(super) fn endpoint_from_url(url: &Url) -> K2Result<EndpointAddr> {
    debug!(
        url = %url,
        "endpoint_from_url: parsing URL to endpoint address"
    );
    let peer_id = url
        .peer_id()
        .ok_or_else(|| {
            error!(url = %url, "endpoint_from_url: URL has no peer ID");
            K2Error::other("url must have peer id")
        })?;
    trace!(
        peer_id,
        "endpoint_from_url: extracted peer ID"
    );
    let endpoint_id = EndpointId::from_str(peer_id).map_err(|err| {
        error!(
            ?err,
            peer_id,
            "endpoint_from_url: failed to convert peer ID to endpoint ID"
        );
        K2Error::other_src("failed to convert peer id to endpoint id", err)
    })?;
    let relay_addr = url.addr();
    let relay_scheme = if url.uses_tls() { "https" } else { "http" };
    trace!(
        relay_addr,
        relay_scheme,
        uses_tls = url.uses_tls(),
        "endpoint_from_url: building relay URL"
    );
    let relay_url = format!("{relay_scheme}://{relay_addr}");
    let relay_url = ::url::Url::from_str(&relay_url)
        .map_err(|err| {
            error!(
                ?err,
                relay_url,
                "endpoint_from_url: failed to parse relay URL"
            );
            K2Error::other_src("invalid relay url", err)
        })?;
    let relay_url = RelayUrl::from(relay_url);
    debug!(
        endpoint_id = ?endpoint_id,
        relay_url = %relay_url,
        "endpoint_from_url: endpoint address created successfully"
    );
    Ok(EndpointAddr::from_parts(
        endpoint_id,
        [TransportAddr::Relay(relay_url)],
    ))
}

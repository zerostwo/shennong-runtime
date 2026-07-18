use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{
    Extension,
    body::Body,
    extract::{
        FromRequestParts, OriginalUri, Path, State,
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Request,
        header::{COOKIE, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use tokio::{sync::watch, time::Instant};
use tokio_tungstenite::{connect_async, tungstenite};
use uuid::Uuid;

use crate::{
    auth::Principal,
    error::{Result, RuntimeError},
    service::AppState,
};

const SESSION_SECRET_HEADER: &str = "x-shennong-session-secret";
const RSTUDIO_REQUEST_HEADER: &str = "x-shennong-rstudio-request";

pub async fn session_proxy_root(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Result<Response> {
    proxy_request(state, principal, id, uri, request).await
}

pub async fn session_proxy_path(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<Principal>,
    Path((id, _path)): Path<(Uuid, String)>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Result<Response> {
    proxy_request(state, principal, id, uri, request).await
}

async fn proxy_request(
    state: Arc<AppState>,
    principal: Principal,
    id: Uuid,
    uri: axum::http::Uri,
    request: Request<Body>,
) -> Result<Response> {
    let target = state.session_proxy_target(&principal, id).await?;
    let target_url = upstream_url(&target.base_url, &uri)?;
    let (mut parts, body) = request.into_parts();
    let websocket = WebSocketUpgrade::from_request_parts(&mut parts, &state)
        .await
        .ok();
    let request = Request::from_parts(parts, body);
    if let Some(websocket) = websocket {
        return proxy_websocket(
            websocket,
            id,
            target_url,
            request.headers(),
            Arc::clone(&state),
            &target.secret,
            target.cancellation,
        )
        .await;
    }
    proxy_http(
        state,
        id,
        target_url,
        request,
        &target.secret,
        target.cancellation,
    )
    .await
}

fn upstream_url(base: &str, original: &axum::http::Uri) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base)
        .map_err(|error| RuntimeError::Internal(format!("invalid session target: {error}")))?;
    url.set_path(original.path());
    url.set_query(original.query());
    Ok(url)
}

async fn proxy_http(
    state: Arc<AppState>,
    session_id: Uuid,
    target: reqwest::Url,
    request: Request<Body>,
    session_secret: &str,
    cancellation: watch::Receiver<bool>,
) -> Result<Response> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let mut request_stream = request.into_body().into_data_stream();
    let mut request_cancellation = cancellation.clone();
    let request_state = Arc::clone(&state);
    let request_body = async_stream::stream! {
        let mut last_touch = Instant::now();
        loop {
            tokio::select! {
                _ = wait_for_cancellation(&mut request_cancellation) => break,
                item = request_stream.next() => {
                    let Some(item) = item else { break; };
                    if !touch_if_due(&request_state, session_id, &mut last_touch).await {
                        break;
                    }
                    yield item;
                }
            }
        }
    };
    let body = reqwest::Body::wrap_stream(request_body);
    let mut upstream = state
        .proxy_client
        .request(method, target.clone())
        .body(body);
    for (name, value) in &headers {
        if forward_request_header(name) {
            upstream = upstream.header(name, value);
        }
    }
    if let Some(cookie) = sanitized_request_cookie(&headers, &state.config.os_auth_cookie_names) {
        upstream = upstream.header(COOKIE, cookie);
    }
    let target_origin = target.origin().ascii_serialization();
    if headers.contains_key("origin") {
        upstream = upstream.header("origin", &target_origin);
    }
    if headers.contains_key("referer") {
        upstream = upstream.header("referer", target.as_str());
    }
    upstream = upstream
        .header(SESSION_SECRET_HEADER, session_secret)
        .header(
            "x-forwarded-prefix",
            format!("/v1/sessions/{session_id}/proxy"),
        )
        .header("x-shennong-session-id", session_id.to_string());
    let mut send_cancellation = cancellation.clone();
    let response = tokio::select! {
        _ = wait_for_cancellation(&mut send_cancellation) => {
            return Err(RuntimeError::Conflict("IDE session proxy was revoked".into()));
        }
        response = upstream.send() => response
            .map_err(|error| RuntimeError::Executor(format!("IDE proxy request failed: {error}")))?,
    };

    let status = response.status();
    let response_headers = response.headers().clone();
    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        if !forward_response_header(name) {
            continue;
        }
        if name == SET_COOKIE {
            if let Some(cookie) = rewrite_set_cookie(session_id, value) {
                builder = builder.header(name, cookie);
            }
        } else if name == axum::http::header::LOCATION
            && let Ok(location) = value.to_str()
            && let Some(relative) = location.strip_prefix(&target_origin)
            && let Ok(relative) = HeaderValue::from_str(relative)
        {
            builder = builder.header(name, relative);
        } else {
            builder = builder.header(name, value);
        }
    }
    let mut response_stream = response.bytes_stream();
    let mut response_cancellation = cancellation;
    let response_state = Arc::clone(&state);
    let response_body = async_stream::stream! {
        let mut last_touch = Instant::now();
        loop {
            tokio::select! {
                _ = wait_for_cancellation(&mut response_cancellation) => break,
                item = response_stream.next() => {
                    let Some(item) = item else { break; };
                    if !touch_if_due(&response_state, session_id, &mut last_touch).await {
                        break;
                    }
                    yield item;
                }
            }
        }
    };
    builder
        .body(Body::from_stream(response_body))
        .map_err(|error| RuntimeError::Internal(error.to_string()))
}

async fn proxy_websocket(
    websocket: WebSocketUpgrade,
    session_id: Uuid,
    mut target: reqwest::Url,
    headers: &HeaderMap,
    state: Arc<AppState>,
    session_secret: &str,
    mut cancellation: watch::Receiver<bool>,
) -> Result<Response> {
    let target_origin = target.origin().ascii_serialization();
    target
        .set_scheme("ws")
        .map_err(|_| RuntimeError::Internal("cannot construct IDE WebSocket URL".into()))?;
    let mut outbound =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            target.as_str(),
        )
        .map_err(|error| {
            RuntimeError::Executor(format!("invalid IDE WebSocket request: {error}"))
        })?;
    for name in ["sec-websocket-protocol"] {
        if let Some(value) = headers.get(name) {
            outbound.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                    RuntimeError::Validation(format!("invalid WebSocket header: {error}"))
                })?,
            );
        }
    }
    copy_rstudio_request_headers(headers, outbound.headers_mut())?;
    if headers.contains_key("origin") {
        outbound.headers_mut().insert(
            HeaderName::from_static("origin"),
            HeaderValue::from_str(&target_origin).map_err(|error| {
                RuntimeError::Internal(format!("invalid IDE Origin header: {error}"))
            })?,
        );
    }
    if let Some(cookie) = sanitized_request_cookie(headers, &state.config.os_auth_cookie_names) {
        outbound.headers_mut().insert(COOKIE, cookie);
    }
    outbound.headers_mut().insert(
        HeaderName::from_static(SESSION_SECRET_HEADER),
        HeaderValue::from_str(session_secret)
            .map_err(|error| RuntimeError::Internal(format!("invalid IDE secret: {error}")))?,
    );
    let (upstream, response) = tokio::select! {
        _ = wait_for_cancellation(&mut cancellation) => {
            return Err(RuntimeError::Conflict("IDE session proxy was revoked".into()));
        }
        connected = connect_async(outbound) => connected.map_err(|error| {
            RuntimeError::Executor(format!("IDE WebSocket connect failed: {error}"))
        })?,
    };
    let selected_protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let websocket = if let Some(protocol) = selected_protocol {
        websocket.protocols([protocol])
    } else {
        websocket
    };
    Ok(websocket
        .on_upgrade(move |client| {
            bridge_websocket(client, upstream, state, session_id, cancellation)
        })
        .into_response())
}

async fn bridge_websocket(
    mut client: WebSocket,
    mut upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    state: Arc<AppState>,
    session_id: Uuid,
    mut cancellation: watch::Receiver<bool>,
) {
    let mut last_touch = Instant::now();
    loop {
        tokio::select! {
            _ = wait_for_cancellation(&mut cancellation) => break,
            incoming = client.recv() => {
                let Some(incoming) = incoming else { break; };
                match incoming {
                    Ok(message) => {
                        if !touch_if_due(&state, session_id, &mut last_touch).await {
                            break;
                        }
                        if let Some(message) = axum_to_tungstenite(message)
                            && upstream.send(message).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "client IDE WebSocket closed with error");
                        break;
                    }
                }
            }
            outgoing = upstream.next() => {
                let Some(outgoing) = outgoing else { break; };
                match outgoing {
                    Ok(message) => {
                        if !touch_if_due(&state, session_id, &mut last_touch).await {
                            break;
                        }
                        if let Some(message) = tungstenite_to_axum(message)
                            && client.send(message).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "upstream IDE WebSocket closed with error");
                        break;
                    }
                }
            }
        }
    }
    let _ = upstream.close(None).await;
    let _ = client.close().await;
}

async fn wait_for_cancellation(cancellation: &mut watch::Receiver<bool>) {
    if *cancellation.borrow() {
        return;
    }
    let _ = cancellation.changed().await;
}

async fn touch_if_due(state: &AppState, session_id: Uuid, last_touch: &mut Instant) -> bool {
    if last_touch.elapsed() < Duration::from_secs(1) {
        return true;
    }
    *last_touch = Instant::now();
    state
        .journal
        .touch_session_activity(session_id)
        .await
        .is_ok()
}

fn axum_to_tungstenite(message: AxumMessage) -> Option<tungstenite::Message> {
    match message {
        AxumMessage::Text(value) => Some(tungstenite::Message::Text(value.to_string().into())),
        AxumMessage::Binary(value) => Some(tungstenite::Message::Binary(value)),
        AxumMessage::Ping(value) => Some(tungstenite::Message::Ping(value)),
        AxumMessage::Pong(value) => Some(tungstenite::Message::Pong(value)),
        AxumMessage::Close(_) => Some(tungstenite::Message::Close(None)),
    }
}

fn tungstenite_to_axum(message: tungstenite::Message) -> Option<AxumMessage> {
    match message {
        tungstenite::Message::Text(value) => Some(AxumMessage::Text(value.to_string().into())),
        tungstenite::Message::Binary(value) => Some(AxumMessage::Binary(value)),
        tungstenite::Message::Ping(value) => Some(AxumMessage::Ping(value)),
        tungstenite::Message::Pong(value) => Some(AxumMessage::Pong(value)),
        tungstenite::Message::Close(_) => Some(AxumMessage::Close(None)),
        tungstenite::Message::Frame(_) => None,
    }
}

fn forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "cookie"
            | "origin"
            | "referer"
            | "connection"
            | "forwarded"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-forwarded-prefix"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-rstudio-request"
            | "x-rstudio-root-path"
            | "x-shennong-session-id"
            | "x-shennong-session-secret"
    )
}

fn copy_rstudio_request_headers(source: &HeaderMap, destination: &mut HeaderMap) -> Result<()> {
    for value in source.get_all(RSTUDIO_REQUEST_HEADER) {
        destination.append(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                RuntimeError::Validation(format!("invalid trusted RStudio request header: {error}"))
            })?,
        );
    }
    Ok(())
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn sanitized_request_cookie(
    headers: &HeaderMap,
    os_auth_cookie_names: &HashSet<String>,
) -> Option<HeaderValue> {
    let mut allowed = Vec::new();
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if valid_cookie_name(name) && !os_auth_cookie_names.contains(name) {
                allowed.push(format!("{name}={value}"));
            }
        }
    }
    (!allowed.is_empty())
        .then(|| HeaderValue::from_str(&allowed.join("; ")).ok())
        .flatten()
}

fn rewrite_set_cookie(session_id: Uuid, value: &HeaderValue) -> Option<HeaderValue> {
    let value = value.to_str().ok()?;
    let mut segments = value.split(';');
    let (name, cookie_value) = segments.next()?.trim().split_once('=')?;
    if !valid_cookie_name(name) {
        return None;
    }
    let mut rewritten = vec![format!("{name}={cookie_value}")];
    for attribute in segments.map(str::trim).filter(|value| !value.is_empty()) {
        let attribute_name = attribute
            .split_once('=')
            .map_or(attribute, |(name, _)| name)
            .trim();
        if !attribute_name.eq_ignore_ascii_case("domain")
            && !attribute_name.eq_ignore_ascii_case("path")
            && !attribute_name.eq_ignore_ascii_case("secure")
        {
            rewritten.push(attribute.to_string());
        }
    }
    rewritten.push(format!("Path=/v1/sessions/{session_id}/proxy/"));
    rewritten.push("Secure".into());
    HeaderValue::from_str(&rewritten.join("; ")).ok()
}

fn forward_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_cookie_filter_preserves_jupyter_cookie_names_and_scopes_set_cookie() {
        let id = Uuid::parse_str("d4158279-57be-4a85-bde8-8ca0f27da90a").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("os_session=do-not-forward; _xsrf=ide-value"),
        );
        let blocked = HashSet::from(["os_session".to_string()]);
        assert_eq!(
            sanitized_request_cookie(&headers, &blocked)
                .unwrap()
                .to_str()
                .unwrap(),
            "_xsrf=ide-value"
        );

        let rewritten = rewrite_set_cookie(
            id,
            &HeaderValue::from_static("_xsrf=new; Domain=os.example; Path=/; HttpOnly"),
        )
        .unwrap();
        let rewritten = rewritten.to_str().unwrap();
        assert!(rewritten.starts_with("_xsrf=new;"));
        assert!(!rewritten.to_ascii_lowercase().contains("domain="));
        assert!(rewritten.contains(&format!("Path=/v1/sessions/{id}/proxy/")));
        assert!(rewritten.contains("Secure"));
    }

    #[test]
    fn only_the_private_rstudio_transport_header_can_cross_the_runtime_proxy() {
        assert!(forward_request_header(&HeaderName::from_static(
            RSTUDIO_REQUEST_HEADER
        )));
        assert!(!forward_request_header(&HeaderName::from_static(
            "x-rstudio-request"
        )));
        assert!(!forward_request_header(&HeaderName::from_static(
            "x-rstudio-root-path"
        )));

        let mut source = HeaderMap::new();
        source.append(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_static("https://ide.example.test/session/proxy/one"),
        );
        source.append(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_static("https://ide.example.test/session/proxy/two"),
        );
        let mut destination = HeaderMap::new();
        copy_rstudio_request_headers(&source, &mut destination).unwrap();
        assert_eq!(
            destination.get_all(RSTUDIO_REQUEST_HEADER).iter().count(),
            2
        );
    }
}

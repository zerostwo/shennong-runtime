use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{
        FromRequestParts, OriginalUri, State,
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header::COOKIE},
    response::{IntoResponse, Response},
    routing::any,
};
use futures_util::{SinkExt, StreamExt};
use reqwest::redirect::Policy;
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite};

const SECRET_HEADER: &str = "x-shennong-session-secret";
const RSTUDIO_REQUEST_HEADER: &str = "x-shennong-rstudio-request";

#[derive(Clone)]
struct GatewayState {
    upstream: reqwest::Url,
    secret_digest: [u8; 32],
    proxy_path: String,
    strip_prefix: bool,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("shennong IDE gateway failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let listen: SocketAddr = required_env("SHENNONG_IDE_GATEWAY_LISTEN")?
        .parse()
        .map_err(|error| format!("invalid IDE gateway listen address: {error}"))?;
    let upstream = reqwest::Url::parse(&required_env("SHENNONG_IDE_GATEWAY_UPSTREAM")?)
        .map_err(|error| format!("invalid IDE gateway upstream: {error}"))?;
    validate_upstream(&upstream)?;
    let secret_digest = required_env("SHENNONG_IDE_GATEWAY_SECRET_SHA256")?;
    let proxy_path = required_env("SHENNONG_IDE_GATEWAY_PROXY_PATH")?;
    validate_proxy_path(&proxy_path)?;
    let strip_prefix = match required_env("SHENNONG_IDE_GATEWAY_STRIP_PREFIX")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("SHENNONG_IDE_GATEWAY_STRIP_PREFIX must be true or false".into()),
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("cannot bind IDE gateway: {error}"))?;
    axum::serve(
        listener,
        gateway_router(upstream, &secret_digest, &proxy_path, strip_prefix)?,
    )
    .await
    .map_err(|error| format!("IDE gateway server error: {error}"))
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn validate_upstream(upstream: &reqwest::Url) -> Result<(), String> {
    if upstream.scheme() != "http"
        || upstream.host_str() != Some("127.0.0.1")
        || upstream.port().is_none()
        || upstream.path() != "/"
        || upstream.query().is_some()
        || upstream.fragment().is_some()
    {
        return Err("IDE gateway upstream must be an http://127.0.0.1:<port>/ URL".into());
    }
    Ok(())
}

fn validate_proxy_path(path: &str) -> Result<(), String> {
    if !path.starts_with("/v1/sessions/") || !path.ends_with("/proxy") || path.contains(['?', '#'])
    {
        return Err("IDE gateway proxy path is invalid".into());
    }
    Ok(())
}

fn gateway_router(
    upstream: reqwest::Url,
    secret_digest: &str,
    proxy_path: &str,
    strip_prefix: bool,
) -> Result<Router, String> {
    let secret_digest: [u8; 32] = hex::decode(secret_digest)
        .map_err(|error| format!("invalid IDE gateway secret digest: {error}"))?
        .try_into()
        .map_err(|_| "IDE gateway secret digest must contain 32 bytes".to_string())?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .redirect(Policy::none())
        .build()
        .map_err(|error| format!("cannot build IDE gateway client: {error}"))?;
    let state = Arc::new(GatewayState {
        upstream,
        secret_digest,
        proxy_path: proxy_path.to_string(),
        strip_prefix,
        client,
    });
    Ok(Router::new()
        .route("/", any(gateway_request))
        .route("/{*path}", any(gateway_request))
        .with_state(state))
}

async fn gateway_request(
    State(state): State<Arc<GatewayState>>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    if !authorized(request.headers(), &state.secret_digest) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Some(upstream_path) = upstream_path(&state, uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut target = state.upstream.clone();
    target.set_path(&upstream_path);
    target.set_query(uri.query());
    let (mut parts, body) = request.into_parts();
    let websocket = WebSocketUpgrade::from_request_parts(&mut parts, &state)
        .await
        .ok();
    let request = Request::from_parts(parts, body);
    let result = if let Some(websocket) = websocket {
        proxy_websocket(websocket, target, request.headers(), &state).await
    } else {
        proxy_http(&state, target, request).await
    };
    result.unwrap_or_else(|error| {
        eprintln!("IDE gateway upstream error: {error}");
        StatusCode::BAD_GATEWAY.into_response()
    })
}

fn authorized(headers: &HeaderMap, expected: &[u8; 32]) -> bool {
    let mut values = headers.get_all(SECRET_HEADER).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    let mut difference = 0_u8;
    for (left, right) in actual.iter().zip(expected) {
        difference |= left ^ right;
    }
    difference == 0
}

fn upstream_path(state: &GatewayState, path: &str) -> Option<String> {
    if path != state.proxy_path
        && !path
            .strip_prefix(&state.proxy_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        return None;
    }
    if !state.strip_prefix {
        return Some(path.to_string());
    }
    Some(
        path.strip_prefix(&state.proxy_path)
            .filter(|suffix| !suffix.is_empty())
            .unwrap_or("/")
            .to_string(),
    )
}

async fn proxy_http(
    state: &GatewayState,
    target: reqwest::Url,
    request: Request<Body>,
) -> Result<Response, String> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let body = reqwest::Body::wrap_stream(request.into_body().into_data_stream());
    let mut upstream = state.client.request(method, target.clone()).body(body);
    for (name, value) in &headers {
        if forward_request_header(name) {
            upstream = upstream.header(name, value);
        }
    }
    if state.strip_prefix {
        upstream = upstream
            .header(
                "x-rstudio-request",
                trusted_rstudio_request(&headers, &state.proxy_path)?,
            )
            .header("x-rstudio-root-path", &state.proxy_path);
    }
    let response = upstream
        .send()
        .await
        .map_err(|error| format!("HTTP proxy failed: {error}"))?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        if forward_response_header(name) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(Body::from_stream(response.bytes_stream()))
        .map_err(|error| format!("cannot build gateway response: {error}"))
}

async fn proxy_websocket(
    websocket: WebSocketUpgrade,
    mut target: reqwest::Url,
    headers: &HeaderMap,
    state: &GatewayState,
) -> Result<Response, String> {
    target
        .set_scheme("ws")
        .map_err(|_| "cannot construct IDE WebSocket URL".to_string())?;
    let mut outbound = tungstenite::client::IntoClientRequest::into_client_request(target.as_str())
        .map_err(|error| format!("invalid IDE WebSocket request: {error}"))?;
    if let Some(value) = headers.get("sec-websocket-protocol") {
        outbound.headers_mut().insert(
            HeaderName::from_static("sec-websocket-protocol"),
            HeaderValue::from_bytes(value.as_bytes())
                .map_err(|error| format!("invalid WebSocket protocol: {error}"))?,
        );
    }
    for name in ["host", "origin", "referer"] {
        if let Some(value) = headers.get(name) {
            outbound.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|error| format!("invalid WebSocket header: {error}"))?,
            );
        }
    }
    if let Some(cookie) = headers.get(COOKIE) {
        outbound.headers_mut().insert(COOKIE, cookie.clone());
    }
    if state.strip_prefix {
        outbound.headers_mut().insert(
            HeaderName::from_static("x-rstudio-request"),
            trusted_rstudio_request(headers, &state.proxy_path)?,
        );
        outbound.headers_mut().insert(
            HeaderName::from_static("x-rstudio-root-path"),
            HeaderValue::from_str(&state.proxy_path)
                .map_err(|error| format!("invalid RStudio root path: {error}"))?,
        );
    }
    let (upstream, response) = connect_async(outbound)
        .await
        .map_err(|error| format!("WebSocket proxy failed: {error}"))?;
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
        .on_upgrade(move |client| bridge_websocket(client, upstream))
        .into_response())
}

async fn bridge_websocket(
    mut client: WebSocket,
    mut upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    loop {
        tokio::select! {
            incoming = client.recv() => {
                let Some(incoming) = incoming else { break; };
                match incoming {
                    Ok(message) => {
                        if let Some(message) = axum_to_tungstenite(message)
                            && upstream.send(message).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            outgoing = upstream.next() => {
                let Some(outgoing) = outgoing else { break; };
                match outgoing {
                    Ok(message) => {
                        if let Some(message) = tungstenite_to_axum(message)
                            && client.send(message).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let _ = upstream.close(None).await;
    let _ = client.close().await;
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

fn trusted_rstudio_request(headers: &HeaderMap, proxy_path: &str) -> Result<HeaderValue, String> {
    let mut values = headers.get_all(RSTUDIO_REQUEST_HEADER).iter();
    let value = values
        .next()
        .ok_or_else(|| "trusted RStudio request URL is missing".to_string())?;
    if values.next().is_some() {
        return Err("trusted RStudio request URL must be unique".into());
    }
    let raw = value
        .to_str()
        .map_err(|_| "trusted RStudio request URL is not valid text".to_string())?;
    let parsed = reqwest::Url::parse(raw)
        .map_err(|_| "trusted RStudio request URL is invalid".to_string())?;
    let path_is_scoped = parsed.path() == proxy_path
        || parsed
            .path()
            .strip_prefix(proxy_path)
            .is_some_and(|suffix| suffix.starts_with('/'));
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || !path_is_scoped
    {
        return Err("trusted RStudio request URL is outside the session proxy".into());
    }
    Ok(value.clone())
}

fn forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "forwarded"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-rstudio-request"
            | "x-rstudio-root-path"
            | RSTUDIO_REQUEST_HEADER
            | SECRET_HEADER
    )
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
    use axum::{
        Json,
        body::{Body, to_bytes},
        extract::ws::{Message as AxumWsMessage, WebSocketUpgrade},
        http::Request,
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_SECRET: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const PROXY_PATH: &str = "/v1/sessions/00000000-0000-4000-8000-000000000000/proxy";

    fn secret_digest() -> String {
        hex::encode(Sha256::digest(SECRET.as_bytes()))
    }

    #[tokio::test]
    async fn missing_or_wrong_secret_is_rejected() {
        let app = gateway_router(
            reqwest::Url::parse("http://127.0.0.1:9/").unwrap(),
            &secret_digest(),
            PROXY_PATH,
            false,
        )
        .unwrap();
        let digest = secret_digest();
        for header in [None, Some("wrong"), Some(digest.as_str())] {
            let mut request = Request::builder().uri(format!("{PROXY_PATH}/private"));
            if let Some(value) = header {
                request = request.header(SECRET_HEADER, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let duplicate = app
            .oneshot(
                Request::builder()
                    .uri(format!("{PROXY_PATH}/private"))
                    .header(SECRET_HEADER, SECRET)
                    .header(SECRET_HEADER, SECRET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::UNAUTHORIZED);

        let other_session = gateway_router(
            reqwest::Url::parse("http://127.0.0.1:9/").unwrap(),
            &hex::encode(Sha256::digest(OTHER_SECRET.as_bytes())),
            PROXY_PATH,
            false,
        )
        .unwrap();
        let cross_session = other_session
            .oneshot(
                Request::builder()
                    .uri(format!("{PROXY_PATH}/private"))
                    .header(SECRET_HEADER, SECRET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_session.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_secret_is_consumed_before_forwarding() {
        let upstream = Router::new().route(
            PROXY_PATH,
            any(|headers: HeaderMap| async move {
                if headers.contains_key(SECRET_HEADER) {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let app = gateway_router(
            reqwest::Url::parse(&format!("http://127.0.0.1:{}/", address.port())).unwrap(),
            &secret_digest(),
            PROXY_PATH,
            false,
        )
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri(PROXY_PATH)
                    .header(SECRET_HEADER, SECRET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rstudio_prefix_is_exactly_stripped_and_proxy_headers_are_trusted() {
        let upstream = Router::new()
            .route(
                "/",
                any(|uri: OriginalUri, headers: HeaderMap| async move {
                    Json(json!({
                        "uri": uri.0.to_string(),
                        "host": headers.get("host").and_then(|value| value.to_str().ok()),
                        "origin": headers.get("origin").and_then(|value| value.to_str().ok()),
                        "root": headers.get("x-rstudio-root-path").and_then(|value| value.to_str().ok()),
                        "request": headers.get("x-rstudio-request").and_then(|value| value.to_str().ok()),
                    }))
                }),
            )
            .fallback(any(
                |uri: OriginalUri, headers: HeaderMap| async move {
                    Json(json!({
                        "uri": uri.0.to_string(),
                        "host": headers.get("host").and_then(|value| value.to_str().ok()),
                        "origin": headers.get("origin").and_then(|value| value.to_str().ok()),
                        "root": headers.get("x-rstudio-root-path").and_then(|value| value.to_str().ok()),
                        "request": headers.get("x-rstudio-request").and_then(|value| value.to_str().ok()),
                    }))
                },
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let app = gateway_router(
            reqwest::Url::parse(&format!("http://127.0.0.1:{}/", address.port())).unwrap(),
            &secret_digest(),
            PROXY_PATH,
            true,
        )
        .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{PROXY_PATH}/folder%20name/file%2Fpart?x=1"))
                    .header(SECRET_HEADER, SECRET)
                    .header("host", "127.0.0.1:18080")
                    .header("origin", "http://127.0.0.1:18080")
                    .header("x-rstudio-request", "https://attacker.invalid/")
                    .header("x-rstudio-root-path", "/attacker")
                    .header(
                        RSTUDIO_REQUEST_HEADER,
                        format!(
                            "https://ide.example.test{PROXY_PATH}/folder%20name/file%2Fpart?x=1"
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{:?}",
            response.headers()
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["uri"], "/folder%20name/file%2Fpart?x=1");
        assert_eq!(body["host"], "127.0.0.1:18080");
        assert_eq!(body["origin"], "http://127.0.0.1:18080");
        assert_eq!(body["root"], PROXY_PATH);
        assert_eq!(
            body["request"],
            format!("https://ide.example.test{PROXY_PATH}/folder%20name/file%2Fpart?x=1")
        );

        let rejected = app
            .oneshot(
                Request::builder()
                    .uri(format!("{PROXY_PATH}evil"))
                    .header(SECRET_HEADER, SECRET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn trusted_rstudio_request_is_unique_http_and_session_scoped() {
        let expected = format!("https://ide.example.test{PROXY_PATH}/path?x=1");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_str(&expected).unwrap(),
        );
        assert_eq!(
            trusted_rstudio_request(&headers, PROXY_PATH)
                .unwrap()
                .to_str()
                .unwrap(),
            expected
        );

        for invalid in [
            "ftp://ide.example.test/v1/sessions/00000000-0000-4000-8000-000000000000/proxy",
            "https://user@ide.example.test/v1/sessions/00000000-0000-4000-8000-000000000000/proxy",
            "https://ide.example.test/not-the-session-proxy",
            "https://ide.example.test/v1/sessions/00000000-0000-4000-8000-000000000000/proxyevil",
            "https://ide.example.test/v1/sessions/00000000-0000-4000-8000-000000000000/proxy#fragment",
        ] {
            headers.insert(
                HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
                HeaderValue::from_static(invalid),
            );
            assert!(trusted_rstudio_request(&headers, PROXY_PATH).is_err());
        }

        headers.insert(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_str(&expected).unwrap(),
        );
        headers.append(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_str(&expected).unwrap(),
        );
        assert!(trusted_rstudio_request(&headers, PROXY_PATH).is_err());
    }

    #[test]
    fn browser_rstudio_headers_and_private_transport_header_are_consumed() {
        for name in [
            "x-rstudio-request",
            "x-rstudio-root-path",
            RSTUDIO_REQUEST_HEADER,
        ] {
            assert!(!forward_request_header(&HeaderName::from_static(name)));
        }
    }

    #[tokio::test]
    async fn websocket_handshake_requires_secret_and_consumes_it() {
        let upstream = Router::new().route(
            &format!("{PROXY_PATH}/ws"),
            any(|headers: HeaderMap, upgrade: WebSocketUpgrade| async move {
                if headers.contains_key(SECRET_HEADER) {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                upgrade
                    .on_upgrade(|mut socket| async move {
                        while let Some(Ok(message)) = socket.recv().await {
                            if let AxumWsMessage::Text(value) = message {
                                let _ = socket.send(AxumWsMessage::Text(value)).await;
                            }
                        }
                    })
                    .into_response()
            }),
        );
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(upstream_listener, upstream).await.unwrap();
        });
        let gateway = gateway_router(
            reqwest::Url::parse(&format!("http://127.0.0.1:{}/", upstream_address.port())).unwrap(),
            &secret_digest(),
            PROXY_PATH,
            false,
        )
        .unwrap();
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gateway_listener, gateway).await.unwrap();
        });
        let url = format!("ws://{gateway_address}{PROXY_PATH}/ws");
        assert!(tokio_tungstenite::connect_async(&url).await.is_err());

        let digest = secret_digest();
        for rejected in ["wrong", digest.as_str()] {
            let mut request =
                tungstenite::client::IntoClientRequest::into_client_request(url.clone()).unwrap();
            request.headers_mut().insert(
                HeaderName::from_static(SECRET_HEADER),
                HeaderValue::from_str(rejected).unwrap(),
            );
            assert!(tokio_tungstenite::connect_async(request).await.is_err());
        }

        let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
        request.headers_mut().insert(
            HeaderName::from_static(SECRET_HEADER),
            HeaderValue::from_static(SECRET),
        );
        let (mut websocket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        websocket
            .send(tungstenite::Message::Text("ping".into()))
            .await
            .unwrap();
        assert_eq!(
            websocket
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
            "ping"
        );
    }

    #[tokio::test]
    async fn websocket_maps_only_the_trusted_rstudio_request_headers() {
        let expected = format!("https://ide.example.test{PROXY_PATH}/ws?client=browser");
        let upstream_expected = expected.clone();
        let upstream = Router::new().route(
            "/ws",
            any(move |headers: HeaderMap, upgrade: WebSocketUpgrade| {
                let expected = upstream_expected.clone();
                async move {
                    let request = headers
                        .get("x-rstudio-request")
                        .and_then(|value| value.to_str().ok());
                    let root = headers
                        .get("x-rstudio-root-path")
                        .and_then(|value| value.to_str().ok());
                    if request != Some(expected.as_str())
                        || root != Some(PROXY_PATH)
                        || headers.contains_key(RSTUDIO_REQUEST_HEADER)
                        || headers.contains_key(SECRET_HEADER)
                    {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    upgrade
                        .on_upgrade(|mut socket| async move {
                            if let Some(Ok(message)) = socket.recv().await {
                                let _ = socket.send(message).await;
                            }
                        })
                        .into_response()
                }
            }),
        );
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(upstream_listener, upstream).await.unwrap();
        });
        let gateway = gateway_router(
            reqwest::Url::parse(&format!("http://127.0.0.1:{}/", upstream_address.port())).unwrap(),
            &secret_digest(),
            PROXY_PATH,
            true,
        )
        .unwrap();
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gateway_listener, gateway).await.unwrap();
        });

        let url = format!("ws://{gateway_address}{PROXY_PATH}/ws?client=browser");
        let mut request = tungstenite::client::IntoClientRequest::into_client_request(url).unwrap();
        request.headers_mut().insert(
            HeaderName::from_static(SECRET_HEADER),
            HeaderValue::from_static(SECRET),
        );
        request.headers_mut().insert(
            HeaderName::from_static(RSTUDIO_REQUEST_HEADER),
            HeaderValue::from_str(&expected).unwrap(),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-rstudio-request"),
            HeaderValue::from_static("https://attacker.invalid/"),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-rstudio-root-path"),
            HeaderValue::from_static("/attacker"),
        );
        let (mut websocket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        websocket
            .send(tungstenite::Message::Text("trusted".into()))
            .await
            .unwrap();
        assert_eq!(
            websocket
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
            "trusted"
        );
    }
}

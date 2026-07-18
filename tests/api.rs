use std::{convert::Infallible, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::ws::{Message as AxumWsMessage, WebSocketUpgrade},
    http::{HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use shennong_runtime::{AppState, RuntimeConfig, auth::RuntimeClaims, router};
use tempfile::TempDir;
use tokio::time::{Duration, interval, sleep, timeout};
use tower::ServiceExt;

const IDE_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestApp {
    app: Router,
    state: Arc<AppState>,
    _directory: TempDir,
}

impl TestApp {
    async fn new() -> Self {
        Self::new_with_limits(4, 2).await
    }

    async fn new_with_limits(max_jobs: usize, max_sessions: usize) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("runtime.db");
        let mut config =
            RuntimeConfig::for_test(format!("sqlite://{}?mode=rwc", database.display()));
        config.max_concurrent_jobs = max_jobs;
        config.max_concurrent_sessions = max_sessions;
        let state = Arc::new(AppState::build(config).await.expect("build app state"));
        state.reconcile().await.expect("reconcile state");
        Self {
            app: router(Arc::clone(&state)),
            state,
            _directory: directory,
        }
    }

    fn token(&self, audience: &str) -> String {
        self.token_with(
            audience,
            vec![
                "runtime:jobs:write",
                "runtime:jobs:read",
                "runtime:jobs:cancel",
                "runtime:sessions:write",
                "runtime:sessions:read",
                "runtime:sessions:proxy",
            ],
            vec!["ws_test123"],
        )
    }

    fn token_with(&self, audience: &str, scopes: Vec<&str>, workspace_refs: Vec<&str>) -> String {
        self.token_with_nbf(audience, scopes, workspace_refs, None)
    }

    fn token_with_nbf(
        &self,
        audience: &str,
        scopes: Vec<&str>,
        workspace_refs: Vec<&str>,
        nbf: Option<i64>,
    ) -> String {
        let now = Utc::now().timestamp();
        encode(
            &Header::default(),
            &RuntimeClaims {
                iss: "shennong-os".into(),
                aud: audience.into(),
                sub: "user_test".into(),
                exp: now + 60,
                iat: now,
                nbf,
                jti: "jti_test_123".into(),
                scopes: scopes.into_iter().map(str::to_owned).collect(),
                workspace_refs: workspace_refs.into_iter().map(str::to_owned).collect(),
            },
            &EncodingKey::from_secret(b"test-secret-at-least-32-bytes-long"),
        )
        .expect("encode JWT")
    }

    async fn request(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        token: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&value).expect("serialize request"))
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).expect("build request"))
            .await
            .expect("router response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes).to_string()}))
        };
        (status, value)
    }
}

#[tokio::test]
async fn concurrent_session_capacity_is_enforced_server_side() {
    let test = TestApp::new_with_limits(1, 1).await;
    let token = test.token("shennong-runtime");
    let (status, first) = test
        .request(
            "POST",
            "/v1/sessions",
            Some(session_spec()),
            Some(&token),
            Some("idem-capacity-session-1"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");

    let (status, response) = test
        .request(
            "POST",
            "/v1/sessions",
            Some(session_spec()),
            Some(&token),
            Some("idem-capacity-session-2"),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{response}");

    let (status, retry) = test
        .request(
            "POST",
            "/v1/sessions",
            Some(session_spec()),
            Some(&token),
            Some("idem-capacity-session-1"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{retry}");
    assert_eq!(retry["id"], first["id"]);
}

#[tokio::test]
async fn wildcard_capabilities_are_not_accepted() {
    let test = TestApp::new().await;
    let wildcard_scope = test.token_with("shennong-runtime", vec!["runtime:*"], vec!["ws_test123"]);
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&wildcard_scope),
            Some("idem-wildcard-scope"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let wildcard_workspace =
        test.token_with("shennong-runtime", vec!["runtime:jobs:write"], vec!["*"]);
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&wildcard_workspace),
            Some("idem-wildcard-workspace"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

fn job_spec() -> Value {
    json!({
        "api_version": "shennong.dev/v1",
        "workspace_ref": "ws_test123",
        "worker_profile": "cpu-small",
        "argv": ["python3", "/workspace/scripts/analysis.py"],
        "resources": {
            "cpus": 1.0,
            "memory_bytes": 536870912,
            "pids": 64,
            "timeout_seconds": 30,
            "tmpfs_bytes": 67108864,
            "max_log_bytes": 65536,
            "max_artifact_bytes": 1048576,
            "max_workspace_bytes": 67108864
        },
        "network": "internet_only",
        "artifact_rules": [{
            "path": "results/mock-result.txt",
            "kind": "other"
        }]
    })
}

fn session_spec() -> Value {
    json!({
        "api_version": "shennong.dev/v1",
        "workspace_ref": "ws_test123",
        "worker_profile": "ide-small",
        "kind": "jupyterlab",
        "resources": {
            "cpus": 1.0,
            "memory_bytes": 1073741824,
            "pids": 128,
            "timeout_seconds": 3600,
            "tmpfs_bytes": 134217728,
            "max_log_bytes": 65536,
            "max_artifact_bytes": 1048576,
            "max_workspace_bytes": 67108864
        },
        "network": "internet_only",
        "idle_timeout_seconds": 300,
        "max_lifetime_seconds": 3600
    })
}

#[tokio::test]
async fn health_is_public_but_jobs_require_a_valid_audience() {
    let test = TestApp::new().await;
    let (status, _) = test.request("GET", "/v1/health", None, None, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = test
        .request("GET", "/v1/jobs/missing", None, None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let wrong_token = test.token("not-the-runtime");
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&wrong_token),
            Some("idem-wrong-audience"),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let future_token = test.token_with_nbf(
        "shennong-runtime",
        vec!["runtime:jobs:write"],
        vec!["ws_test123"],
        Some(Utc::now().timestamp() + 60),
    );
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&future_token),
            Some("idem-future-nbf"),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn submit_is_idempotent_and_exposes_bounded_logs_and_artifacts() {
    let test = TestApp::new().await;
    let token = test.token("shennong-runtime");
    let (status, first) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&token),
            Some("idem-job-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let id = first["id"].as_str().expect("job id");

    let (status, second) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&token),
            Some("idem-job-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(second["id"], first["id"]);

    sleep(Duration::from_millis(250)).await;
    let (status, job) = test
        .request("GET", &format!("/v1/jobs/{id}"), None, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{job}");
    assert_eq!(job["state"], "succeeded");

    let (status, logs) = test
        .request(
            "GET",
            &format!("/v1/jobs/{id}/logs?after=0&limit=10"),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(logs["entries"].as_array().expect("log entries").len(), 1);
    assert!(logs["next_cursor"].as_i64().expect("cursor") > 0);

    let (status, artifacts) = test
        .request(
            "GET",
            &format!("/v1/jobs/{id}/artifacts"),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        artifacts["artifacts"][0]["relative_path"],
        "results/mock-result.txt"
    );
}

#[tokio::test]
async fn workspace_quota_is_enforced_before_and_during_jobs_and_sessions() {
    let test = TestApp::new().await;
    for (workspace, expected_status, id_suffix) in [
        ("ws_preoverquota", StatusCode::UNPROCESSABLE_ENTITY, "pre"),
        ("ws_overquota", StatusCode::ACCEPTED, "runtime"),
        ("ws_quotaerror", StatusCode::ACCEPTED, "measurement"),
    ] {
        let token = test.token_with(
            "shennong-runtime",
            vec![
                "runtime:jobs:write",
                "runtime:jobs:read",
                "runtime:sessions:write",
                "runtime:sessions:read",
            ],
            vec![workspace],
        );
        let mut job = job_spec();
        job["workspace_ref"] = json!(workspace);
        let (status, submitted) = test
            .request(
                "POST",
                "/v1/jobs",
                Some(job),
                Some(&token),
                Some(&format!("idem-quota-job-{id_suffix}")),
            )
            .await;
        assert_eq!(status, expected_status, "{submitted}");
        if status == StatusCode::ACCEPTED {
            sleep(Duration::from_millis(250)).await;
            let id = submitted["id"].as_str().expect("job id");
            let (status, job) = test
                .request("GET", &format!("/v1/jobs/{id}"), None, Some(&token), None)
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(job["state"], "failed", "{job}");
            assert!(
                job["error"]
                    .as_str()
                    .expect("quota error")
                    .contains("workspace quota")
            );
        }

        let mut session = session_spec();
        session["workspace_ref"] = json!(workspace);
        let (status, submitted) = test
            .request(
                "POST",
                "/v1/sessions",
                Some(session),
                Some(&token),
                Some(&format!("idem-quota-session-{id_suffix}")),
            )
            .await;
        assert_eq!(status, expected_status, "{submitted}");
        if status == StatusCode::ACCEPTED {
            sleep(Duration::from_millis(250)).await;
            let id = submitted["id"].as_str().expect("session id");
            let (status, session) = test
                .request(
                    "GET",
                    &format!("/v1/sessions/{id}"),
                    None,
                    Some(&token),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(session["state"], "failed", "{session}");
            assert!(
                session["error"]
                    .as_str()
                    .expect("quota error")
                    .contains("workspace quota")
            );
        }
    }
}

#[tokio::test]
async fn session_idle_timeout_is_enforced_and_activity_wins_the_atomic_race() {
    let test = TestApp::new().await;
    let token = test.token("shennong-runtime");
    let (status, submitted) = test
        .request(
            "POST",
            "/v1/sessions",
            Some(session_spec()),
            Some(&token),
            Some("idem-idle-session-1"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{submitted}");
    let id = submitted["id"]
        .as_str()
        .expect("session id")
        .parse()
        .expect("session UUID");
    test.state
        .journal
        .set_session_activity(id, Utc::now() - chrono::Duration::seconds(600))
        .await
        .expect("age session activity");
    sleep(Duration::from_millis(150)).await;
    let record = test
        .state
        .journal
        .session(id)
        .await
        .expect("expired session");
    assert_eq!(
        record.view.state,
        shennong_runtime::model::SessionState::Expired
    );
    assert!(
        record
            .view
            .error
            .expect("idle expiry reason")
            .contains("idle timeout")
    );

    let spec: shennong_runtime::model::SessionSpec =
        serde_json::from_value(session_spec()).expect("session spec");
    let active = test
        .state
        .journal
        .insert_session("user_test", "idem-idle-atomic", "hash", &spec)
        .await
        .expect("insert atomic session");
    let before_activation = Utc::now() - chrono::Duration::seconds(600);
    test.state
        .journal
        .set_session_activity(active.view.id, before_activation)
        .await
        .expect_err("starting session cannot be touched");
    test.state
        .journal
        .activate_session(
            active.view.id,
            "atomic-fixture",
            "http://127.0.0.1:9",
            IDE_SECRET,
        )
        .await
        .expect("activate atomic session");
    test.state
        .journal
        .set_session_activity(active.view.id, Utc::now() - chrono::Duration::seconds(301))
        .await
        .expect("age atomic session");
    test.state
        .journal
        .touch_session_activity(active.view.id)
        .await
        .expect("record concurrent activity first");
    assert!(
        !test
            .state
            .journal
            .expire_session_if_idle(
                active.view.id,
                Utc::now() - chrono::Duration::seconds(300),
                "must not win stale race",
            )
            .await
            .expect("conditional expiry")
    );
    assert_eq!(
        test.state
            .journal
            .session(active.view.id)
            .await
            .expect("active session")
            .view
            .state,
        shennong_runtime::model::SessionState::Running
    );
}

#[tokio::test]
async fn strict_schema_shell_and_idempotency_reuse_are_rejected() {
    let test = TestApp::new().await;
    let token = test.token("shennong-runtime");
    let mut shell = job_spec();
    shell["argv"] = json!(["bash", "-c", "id"]);
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(shell),
            Some(&token),
            Some("idem-shell-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(job_spec()),
            Some(&token),
            Some("idem-conflict-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mut changed = job_spec();
    changed["argv"] = json!(["python3", "different.py"]);
    let (status, _) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(changed),
            Some(&token),
            Some("idem-conflict-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let mut unknown = job_spec();
    unknown["unexpected"] = json!(true);
    let (status, response) = test
        .request(
            "POST",
            "/v1/jobs",
            Some(unknown),
            Some(&token),
            Some("idem-unknown-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn ide_session_returns_only_an_internal_proxy_target() {
    let test = TestApp::new().await;
    let token = test.token("shennong-runtime");
    let (status, session) = test
        .request(
            "POST",
            "/v1/sessions",
            Some(session_spec()),
            Some(&token),
            Some("idem-session-0001"),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{session}");
    assert_eq!(session["state"], "running");
    let proxy_path = session["proxy_path"].as_str().expect("proxy path");
    assert!(proxy_path.ends_with("/proxy/"));
    assert!(session.get("internal_target").is_none());

    let id = session["id"].as_str().expect("session id");
    let (status, stopped) = test
        .request(
            "POST",
            &format!("/v1/sessions/{id}/stop"),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stopped}");
    assert_eq!(stopped["state"], "stopped");
}

#[tokio::test]
async fn session_proxy_reaches_loopback_and_strips_the_os_bearer_token() {
    let test = TestApp::new().await;
    let upstream = Router::new().route(
        "/v1/sessions/{id}/proxy/hello",
        get(|headers: HeaderMap| async move {
            Json(json!({
                "authorization_forwarded": headers.contains_key("authorization"),
                "gateway_secret": headers
                    .get("x-shennong-session-secret")
                    .and_then(|value| value.to_str().ok()),
                "forwarded_prefix": headers
                    .get("x-forwarded-prefix")
                    .and_then(|value| value.to_str().ok())
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback IDE fixture");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.expect("IDE fixture");
    });

    let spec: shennong_runtime::model::SessionSpec =
        serde_json::from_value(session_spec()).expect("session spec");
    let record = test
        .state
        .journal
        .insert_session("user_test", "idem-proxy-fixture", "hash", &spec)
        .await
        .expect("insert proxy session");
    test.state
        .journal
        .activate_session(
            record.view.id,
            "fixture",
            &format!("http://127.0.0.1:{}", address.port()),
            IDE_SECRET,
        )
        .await
        .expect("activate proxy session");

    let token = test.token("shennong-runtime");
    let (status, response) = test
        .request(
            "GET",
            &format!("/v1/sessions/{}/proxy/hello", record.view.id),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["authorization_forwarded"], false);
    assert_eq!(response["gateway_secret"], IDE_SECRET);
    assert_eq!(
        response["forwarded_prefix"],
        format!("/v1/sessions/{}/proxy", record.view.id)
    );

    let override_attempt = test
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/sessions/{}/proxy/hello", record.view.id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-shennong-session-secret", "attacker-controlled")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(override_attempt.status(), StatusCode::OK);
    let override_body: Value =
        serde_json::from_slice(&to_bytes(override_attempt.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(override_body["gateway_secret"], IDE_SECRET);
}

#[tokio::test]
async fn long_http_proxy_stream_tracks_activity_and_is_revoked_on_stop() {
    let test = TestApp::new().await;
    let upstream = Router::new().route(
        "/v1/sessions/{id}/proxy/stream",
        get(|headers: HeaderMap| async move {
            if headers
                .get("x-shennong-session-secret")
                .and_then(|value| value.to_str().ok())
                != Some(IDE_SECRET)
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            let body = async_stream::stream! {
                for _ in 0..100 {
                    yield Ok::<_, Infallible>("chunk\n");
                    sleep(Duration::from_millis(100)).await;
                }
            };
            Body::from_stream(body).into_response()
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind streaming IDE fixture");
    let upstream_address = upstream_listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        axum::serve(upstream_listener, upstream)
            .await
            .expect("streaming IDE fixture");
    });
    let spec: shennong_runtime::model::SessionSpec =
        serde_json::from_value(session_spec()).expect("session spec");
    let record = test
        .state
        .journal
        .insert_session("user_test", "idem-http-stream", "hash", &spec)
        .await
        .expect("insert streaming session");
    test.state
        .journal
        .activate_session(
            record.view.id,
            "fixture-http-stream",
            &format!("http://127.0.0.1:{}", upstream_address.port()),
            IDE_SECRET,
        )
        .await
        .expect("activate streaming session");

    let runtime_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Runtime fixture");
    let runtime_address = runtime_listener.local_addr().expect("Runtime address");
    let runtime_app = test.app.clone();
    tokio::spawn(async move {
        axum::serve(runtime_listener, runtime_app)
            .await
            .expect("Runtime fixture");
    });
    let token = test.token("shennong-runtime");
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP client")
        .get(format!(
            "http://{runtime_address}/v1/sessions/{}/proxy/stream",
            record.view.id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("open Runtime stream");
    assert_eq!(response.status(), StatusCode::OK);
    let activity_before = test
        .state
        .journal
        .session(record.view.id)
        .await
        .expect("session before response activity")
        .last_activity_at;
    let mut stream = response.bytes_stream();
    assert!(stream.next().await.is_some());
    sleep(Duration::from_millis(1_100)).await;
    let activity_after = test
        .state
        .journal
        .session(record.view.id)
        .await
        .expect("session after response activity")
        .last_activity_at;
    assert!(activity_after > activity_before);

    let (status, stopped) = test
        .request(
            "POST",
            &format!("/v1/sessions/{}/stop", record.view.id),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stopped}");
    timeout(Duration::from_secs(1), async {
        while stream.next().await.is_some() {}
    })
    .await
    .expect("revoked HTTP stream must end promptly");
}

#[tokio::test]
async fn session_proxy_bridges_websockets_end_to_end() {
    let test = TestApp::new().await;
    let upstream = Router::new().route(
        "/v1/sessions/{id}/proxy/ws",
        get(|headers: HeaderMap, upgrade: WebSocketUpgrade| async move {
            if headers
                .get("x-shennong-session-secret")
                .and_then(|value| value.to_str().ok())
                != Some(IDE_SECRET)
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            upgrade
                .on_upgrade(|mut socket| async move {
                    let mut ticker = interval(Duration::from_millis(100));
                    loop {
                        tokio::select! {
                            _ = ticker.tick() => {
                                if socket
                                    .send(AxumWsMessage::Text("server-tick".into()))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            incoming = socket.recv() => {
                                let Some(Ok(message)) = incoming else { break; };
                                match message {
                                    AxumWsMessage::Text(value) => {
                                        if socket.send(AxumWsMessage::Text(value)).await.is_err() {
                                            break;
                                        }
                                    }
                                    AxumWsMessage::Close(_) => break,
                                    _ => {}
                                }
                            }
                        }
                    }
                })
                .into_response()
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind WebSocket IDE fixture");
    let upstream_address = upstream_listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        axum::serve(upstream_listener, upstream)
            .await
            .expect("WebSocket IDE fixture");
    });

    let spec: shennong_runtime::model::SessionSpec =
        serde_json::from_value(session_spec()).expect("session spec");
    let record = test
        .state
        .journal
        .insert_session("user_test", "idem-ws-fixture", "hash", &spec)
        .await
        .expect("insert WebSocket proxy session");
    test.state
        .journal
        .activate_session(
            record.view.id,
            "fixture",
            &format!("http://127.0.0.1:{}", upstream_address.port()),
            IDE_SECRET,
        )
        .await
        .expect("activate WebSocket proxy session");

    let runtime_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Runtime fixture");
    let runtime_address = runtime_listener.local_addr().expect("Runtime address");
    let runtime_app = test.app.clone();
    tokio::spawn(async move {
        axum::serve(runtime_listener, runtime_app)
            .await
            .expect("Runtime fixture");
    });

    let url = format!(
        "ws://{runtime_address}/v1/sessions/{}/proxy/ws",
        record.view.id
    );
    let mut request =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
            .expect("WebSocket client request");
    let token = test.token("shennong-runtime");
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .expect("authorization header"),
    );
    let (mut websocket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("connect through Runtime WebSocket proxy");
    let activity_before = test
        .state
        .journal
        .session(record.view.id)
        .await
        .expect("session before server activity")
        .last_activity_at;
    websocket
        .send(tokio_tungstenite::tungstenite::Message::Text("ping".into()))
        .await
        .expect("send WebSocket message");
    loop {
        let echoed = websocket
            .next()
            .await
            .expect("echo response")
            .expect("valid echo");
        if echoed.into_text().expect("text echo") == "ping" {
            break;
        }
    }
    sleep(Duration::from_millis(1_100)).await;
    let activity_after = test
        .state
        .journal
        .session(record.view.id)
        .await
        .expect("session after server activity")
        .last_activity_at;
    assert!(activity_after > activity_before);

    let (status, stopped) = test
        .request(
            "POST",
            &format!("/v1/sessions/{}/stop", record.view.id),
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stopped}");
    timeout(Duration::from_secs(1), async {
        while let Some(message) = websocket.next().await {
            match message {
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await
    .expect("revoked WebSocket must close promptly");
}

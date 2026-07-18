use std::sync::Arc;

use shennong_runtime::{AppState, RuntimeConfig, router};
use tokio::net::TcpListener;
use tower_http::{request_id::MakeRequestUuid, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("shennong_runtime=info,tower_http=info")),
        )
        .init();

    let config = RuntimeConfig::from_env()?;
    let listen = config.listen;
    let state = Arc::new(AppState::build(config).await?);
    state.reconcile().await?;
    state.spawn_maintenance();

    let app = router(state).layer(TraceLayer::new_for_http()).layer(
        tower_http::request_id::SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ),
    );

    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "shennong runtime listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn healthcheck() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let address =
        std::env::var("SHENNONG_RUNTIME_HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:7000".into());
    let mut stream =
        TcpStream::connect_timeout(&address.parse()?, std::time::Duration::from_secs(2))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.write_all(b"GET /v1/health HTTP/1.1\r\nHost: runtime\r\nConnection: close\r\n\r\n")?;
    let mut response = [0_u8; 64];
    let read = stream.read(&mut response)?;
    if response[..read].starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err("runtime health endpoint did not return HTTP 200".into())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

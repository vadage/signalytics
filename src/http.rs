use crate::db::top_ciphers;
use crate::families::expand;
use crate::models::FingerprintParams;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use sqlx::MySqlPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, warn};

#[derive(Clone)]
struct AppState {
    pool: MySqlPool,
    retention_days: Option<u32>,
    families: Arc<Vec<(String, String)>>,
}

pub async fn run_http_server(
    listener: TcpListener,
    pool: MySqlPool,
    retention_days: Option<u32>,
    families: Vec<(String, String)>,
) {
    let state = AppState {
        pool,
        retention_days,
        families: Arc::new(families),
    };
    let app = Router::new()
        .route("/", get(health))
        .route("/healthz", get(health))
        .route("/fingerprints", get(fingerprints))
        .with_state(state);

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = ?e, "HTTP server stopped");
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn fingerprints(
    State(state): State<AppState>,
    Query(params): Query<FingerprintParams>,
) -> Result<Json<Value>, (StatusCode, &'static str)> {
    if let Some(retention_days) = state.retention_days
        && params.days > retention_days
    {
        warn!(
            days = params.days,
            retention_days, "Requested more days than are retained"
        );
    }

    let fingerprints = top_ciphers(&state.pool, &state.families, &params)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to query fingerprints");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query fingerprints",
            )
        })?;

    // Refuse short lists, so a broken query or an empty database never replaces a good export.
    if fingerprints.len() < params.min_count {
        warn!(
            count = fingerprints.len(),
            min_count = params.min_count,
            "Too few fingerprints found"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Too few fingerprints found",
        ));
    }

    Ok(Json(
        json!({ "tls_client_ciphers_sha1": expand(fingerprints, &state.families) }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(query: &str) -> Result<FingerprintParams, String> {
        let uri = format!("http://localhost/fingerprints{query}")
            .parse()
            .unwrap();
        Query::<FingerprintParams>::try_from_uri(&uri)
            .map(|Query(params)| params)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn test_params_defaults() {
        assert_eq!(parse(""), Ok(FingerprintParams::default()));
    }

    #[test]
    fn test_params_overrides() {
        let expected = FingerprintParams {
            days: 7,
            min_days: 1,
            min_hits: 0,
            min_prefixes: 2,
            min_asns: 3,
            min_hosts: 4,
            limit: 10,
            min_count: 1,
        };
        assert_eq!(
            parse(
                "?days=7&min_days=1&min_hits=0&min_prefixes=2&min_asns=3&min_hosts=4&limit=10&min_count=1"
            ),
            Ok(expected)
        );
    }

    #[test]
    fn test_params_invalid() {
        assert!(parse("?days=abc").is_err());
        assert!(parse("?limit=-1").is_err());
    }
}

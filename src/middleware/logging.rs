use axum::{extract::Request, http::HeaderMap, middleware::Next, response::Response};
use tracing::{Instrument, Level, info, span};
use uuid::Uuid;

const TRACE_ID_HEADER: &str = "trace-id";

pub async fn log_requests(req: Request, next: Next) -> Response {
    let trace_id = get_trace_id(req.headers());
    let method = req.method();
    let path = req.uri().path().to_string();

    let headers = req.headers();
    let content_length = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .to_string();
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let span = span!(
        Level::INFO,
        "request",
        trace_id = %trace_id,
        method = %method,
        path = %path,
    );

    async move {
        info!(
            content_length = %content_length,
            content_type = %content_type,
            "incoming request"
        );

        let response = next.run(req).await;

        let status = response.status();
        let response_content_length = response
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unset");

        info!(
            status = %status,
            content_length = response_content_length,
            "request completed"
        );

        response
    }
    .instrument(span)
    .await
}

fn get_trace_id(headers: &HeaderMap) -> String {
    headers
        .get(TRACE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

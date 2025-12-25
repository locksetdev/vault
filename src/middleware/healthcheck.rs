use axum::{extract::Request, middleware::Next, response::Response};

pub async fn healthcheck(req: Request, next: Next) -> Response {
    let method = req.method();
    let path = req.uri().path().to_string();

    if method == axum::http::Method::GET && path == "/healthcheck" {
        return Response::builder()
            .status(axum::http::StatusCode::OK)
            .body(axum::body::Body::from("OK"))
            .unwrap();
    }

    next.run(req).await
}

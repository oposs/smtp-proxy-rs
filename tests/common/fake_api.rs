//! In-process stand-in for the customer's API (spec 5.3), port of
//! `FakeAPI.pm`. Records every request body it receives so tests can assert
//! on the exact JSON the client sent.
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

#[derive(Clone)]
pub struct FakeApi {
    pub url: String,
    state: Arc<Mutex<FakeApiState>>,
}

pub struct FakeApiState {
    pub response: serde_json::Value,
    pub status: StatusCode,
    pub calls: Vec<serde_json::Value>,
}

async fn handle(
    State(state): State<Arc<Mutex<FakeApiState>>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut s = state.lock().unwrap();
    s.calls.push(body);
    (s.status, Json(s.response.clone()))
}

impl FakeApi {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(FakeApiState {
            response: serde_json::json!({ "allow": true, "headers": [] }),
            status: StatusCode::OK,
            calls: Vec::new(),
        }));
        let app = Router::new()
            .route("/check", post(handle))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/check", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state }
    }

    pub fn respond(&self, response: serde_json::Value) {
        let mut s = self.state.lock().unwrap();
        s.response = response;
        s.status = StatusCode::OK;
    }

    pub fn fail_with(&self, status: StatusCode) {
        self.state.lock().unwrap().status = status;
    }

    pub fn calls(&self) -> Vec<serde_json::Value> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().calls.clear();
    }
}

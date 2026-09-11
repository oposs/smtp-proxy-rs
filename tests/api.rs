//! Integration tests for the API client against `FakeApi` (spec 5.3).
mod common;

use std::sync::{Arc, Mutex, OnceLock};

use common::fake_api::FakeApi;
use smtp_proxy::api::{ApiClient, ApiError, CheckRequest, Recipient, RequestHeader};
use smtp_proxy::smtp::params::Param;
use tracing_subscriber::prelude::*;

/// Every line this binary logs. It has to be installed *globally* and
/// before any test has evaluated one of the callsites under assertion:
/// `tracing` caches each callsite's interest process wide, so a callsite
/// first reached with no subscriber stays disabled for every later test. So
/// every test in this binary calls this, not only the one that reads it.
fn captured_log() -> &'static Mutex<Vec<u8>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = buffer.clone();
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || Capture(sink.clone()))
                    .with_filter(tracing::level_filters::LevelFilter::DEBUG),
            )
            .init();
        buffer
    })
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn request() -> CheckRequest {
    CheckRequest {
        username: "u".into(),
        password: "secret".into(),
        from: "a@b.com".into(),
        to: vec!["x@baz.com".into(), "x@baz.com".into()],
        headers: vec![RequestHeader {
            name: "To".into(),
            value: "foo@bar.com".into(),
        }],
        mail_parameters: vec![Param {
            keyword: "RET".into(),
            value: Some("HDRS".into()),
        }],
        rcpt_parameters: vec![
            Recipient {
                address: "x@baz.com".into(),
                parameters: vec![Param {
                    keyword: "NOTIFY".into(),
                    value: Some("SUCCESS".into()),
                }],
            },
            Recipient {
                address: "x@baz.com".into(),
                parameters: vec![Param {
                    keyword: "SMTPUTF8".into(),
                    value: None,
                }],
            },
        ],
    }
}

#[tokio::test]
async fn request_body_matches_the_contract() {
    captured_log();
    let api = FakeApi::start().await;
    let client = ApiClient::new(api.url.clone()).unwrap();
    let resp = client.check(&request()).await.unwrap();
    assert!(resp.allow);
    let call = &api.calls()[0];
    let expected = serde_json::json!({
        "username": "u", "password": "secret", "from": "a@b.com",
        "to": ["x@baz.com", "x@baz.com"],
        "headers": [{"name": "To", "value": "foo@bar.com"}],
        "mailParameters": [{"keyword": "RET", "value": "HDRS"}],
        "rcptParameters": [
            {"address": "x@baz.com", "parameters": [{"keyword": "NOTIFY", "value": "SUCCESS"}]},
            {"address": "x@baz.com", "parameters": [{"keyword": "SMTPUTF8", "value": null}]}
        ]
    });
    assert_eq!(call, &expected);
    // Field order is part of the contract.
    let raw = serde_json::to_string(&request()).unwrap();
    let keys: Vec<&str> = [
        "\"username\"",
        "\"password\"",
        "\"from\"",
        "\"to\"",
        "\"headers\"",
        "\"mailParameters\"",
        "\"rcptParameters\"",
    ]
    .into();
    let positions: Vec<usize> = keys.iter().map(|k| raw.find(k).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{raw}");
}

#[tokio::test]
async fn deny_and_optional_fields() {
    captured_log();
    let api = FakeApi::start().await;
    api.respond(serde_json::json!({ "allow": false, "reason": "sorry, not telling" }));
    let client = ApiClient::new(api.url.clone()).unwrap();
    let resp = client.check(&request()).await.unwrap();
    assert!(!resp.allow);
    assert_eq!(resp.reason.as_deref(), Some("sorry, not telling"));
    assert!(resp.headers.is_empty());
    api.respond(serde_json::json!({
        "allow": true,
        "headers": [{"name": "X", "value": null}],
        "from": "o@b.com",
        "authId": "tok"
    }));
    let resp = client.check(&request()).await.unwrap();
    assert_eq!(resp.headers[0].value, None);
    assert_eq!(resp.from.as_deref(), Some("o@b.com"));
    assert_eq!(resp.auth_id.as_deref(), Some("tok"));
}

#[tokio::test]
async fn non_2xx_is_an_error_carrying_the_reason_phrase() {
    captured_log();
    let api = FakeApi::start().await;
    api.fail_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let client = ApiClient::new(api.url.clone()).unwrap();
    match client.check(&request()).await {
        Err(ApiError::Status(500, reason)) => assert_eq!(reason, "Internal Server Error"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn unreachable_api_is_a_transport_error() {
    captured_log();
    let client = ApiClient::new("http://127.0.0.1:1/check".into()).unwrap();
    assert!(matches!(
        client.check(&request()).await,
        Err(ApiError::Transport(_))
    ));
}

/// M4 and M6. Every call logs that the API answered and with what code,
/// and a body that is not the agreed JSON gets the spec-5.3 redacted
/// request dump that a 500 or a refused connection already got.
#[tokio::test]
async fn invalid_json_is_an_error_and_still_dumps_the_redacted_request() {
    let log = captured_log();
    let api = FakeApi::start().await;
    api.respond_raw("<html>not json at all</html>", "text/html");
    let client = ApiClient::new(api.url.clone()).unwrap();
    // Unique to this test, so its lines can be picked out of a log that
    // every other test in this binary writes to as well.
    let mut request = request();
    request.from = "json-error-probe@b.com".into();
    let result = client.check(&request).await;
    assert!(matches!(result, Err(ApiError::Json(_))), "{result:?}");
    let text = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    let dumps: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("json-error-probe@b.com"))
        .collect();
    assert_eq!(dumps.len(), 1, "{text}");
    assert!(dumps[0].contains("*******"), "{}", dumps[0]);
    assert!(!dumps[0].contains("secret"), "{}", dumps[0]);
    let calls: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(&format!("validation call to {} returned 200", api.url)))
        .collect();
    assert_eq!(calls.len(), 1, "{text}");
}

#[test]
fn redacted_json_hides_the_password() {
    let json = request().redacted_json();
    assert!(json.contains("\"password\":\"*******\""), "{json}");
    assert!(!json.contains("secret"));
}

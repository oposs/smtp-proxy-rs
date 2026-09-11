//! The authentication and header API (spec 5.3): one POST per message,
//! asking the customer's HTTP endpoint whether the mail may be sent.
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::smtp::params::Param;

/// One entry of the request's `headers` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHeader {
    pub name: String,
    pub value: String,
}

/// One entry of the response's `headers` array. Unlike the request side,
/// the API may send back a header with no value, meaning "remove this
/// header without replacing it" (spec 5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHeader {
    pub name: String,
    pub value: Option<String>,
}

/// One RCPT TO as given, in order. Also the `rcptParameters` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub address: String,
    pub parameters: Vec<Param>,
}

/// The body of the API call. Field order is the wire contract (spec 5.3)
/// and follows declaration order under `derive(Serialize)`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckRequest {
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub headers: Vec<RequestHeader>,
    #[serde(rename = "mailParameters")]
    pub mail_parameters: Vec<Param>,
    #[serde(rename = "rcptParameters")]
    pub rcpt_parameters: Vec<Recipient>,
}

impl CheckRequest {
    /// The request as JSON with the password replaced by `*******`, safe to
    /// log. Field order is not the wire order here (it goes through
    /// `Value`, which sorts keys); that is fine for a debug line.
    pub fn redacted_json(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "password".into(),
                serde_json::Value::String("*******".into()),
            );
        }
        value.to_string()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CheckResponse {
    pub allow: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub headers: Vec<ResponseHeader>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default, rename = "authId")]
    pub auth_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Transport(#[from] reqwest::Error),
    /// Non-2xx. The string is the HTTP reason phrase (Perl: `$tx->result->message`), e.g. `Internal Server Error`.
    #[error("{1}")]
    Status(u16, String),
    #[error("invalid JSON from the API: {0}")]
    Json(String),
}

/// Client for the `--api` endpoint. Cheap to clone: the inner
/// `reqwest::Client` is itself a cheap `Arc` handle.
#[derive(Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    url: String,
}

impl ApiClient {
    /// 60 second timeout, as the Perl inactivity timeout.
    pub fn new(url: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self { client, url })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Asks the API whether `request` may be sent. Non-2xx and transport
    /// errors both log the redacted request at debug before returning
    /// (spec 5.3); the caller logs the warn/info lines that name the
    /// client, since only the caller has the connection id.
    pub async fn check(&self, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
        let result = self.post(request).await;
        if let Err(ApiError::Transport(_) | ApiError::Status(_, _)) = &result {
            tracing::debug!("{}", request.redacted_json());
        }
        result
    }

    async fn post(&self, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
        let response = self.client.post(&self.url).json(request).send().await?;
        let status = response.status();
        if !status.is_success() {
            let reason = status.canonical_reason().unwrap_or_default().to_string();
            return Err(ApiError::Status(status.as_u16(), reason));
        }
        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Json(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CheckRequest {
        CheckRequest {
            username: "u".into(),
            password: "secret".into(),
            from: "a@b.com".into(),
            to: vec!["x@baz.com".into()],
            headers: vec![],
            mail_parameters: vec![],
            rcpt_parameters: vec![],
        }
    }

    #[test]
    fn field_order_matches_the_wire_contract() {
        let raw = serde_json::to_string(&request()).unwrap();
        let keys = [
            "\"username\"",
            "\"password\"",
            "\"from\"",
            "\"to\"",
            "\"headers\"",
            "\"mailParameters\"",
            "\"rcptParameters\"",
        ];
        let positions: Vec<usize> = keys.iter().map(|k| raw.find(k).unwrap()).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{raw}");
    }

    #[test]
    fn redacted_json_hides_the_password() {
        let json = request().redacted_json();
        assert!(json.contains("\"password\":\"*******\""), "{json}");
        assert!(!json.contains("secret"));
    }

    #[test]
    fn valueless_parameter_serialises_as_null() {
        let json = serde_json::to_string(&Recipient {
            address: "x@baz.com".into(),
            parameters: vec![Param {
                keyword: "SMTPUTF8".into(),
                value: None,
            }],
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"address":"x@baz.com","parameters":[{"keyword":"SMTPUTF8","value":null}]}"#
        );
    }
}

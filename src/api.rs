//! The authentication and header API (spec 5.3): one POST per message,
//! asking the customer's HTTP endpoint whether the mail may be sent.
use std::fmt;
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
#[derive(Clone, Serialize)]
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

/// Hand-written rather than derived: the password must never reach a log
/// through a stray `{:?}`, `tracing::debug!(?request)`, or a panicking
/// `.expect()` on a `Result` that holds this struct — not just through the
/// one call site this module happens to log from today.
impl fmt::Debug for CheckRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckRequest")
            .field("username", &self.username)
            .field("password", &"*******")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("headers", &self.headers)
            .field("mail_parameters", &self.mail_parameters)
            .field("rcpt_parameters", &self.rcpt_parameters)
            .finish()
    }
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

/// `Serialize` is here for the debug dump only; nothing ever sends this
/// back to the API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl CheckResponse {
    /// The answer as JSON, for the dump on the relay-failure path. Unlike
    /// [`CheckRequest::redacted_json`] there is nothing to redact: the
    /// response carries no credential, and `authId` is the token name that
    /// both this proxy and the Perl already write to the main log at info
    /// on every relayed mail (`SMTPProxy.pm:310`). The Perl's counterpart
    /// dumps the decoded response whole (`SMTPProxy.pm:299`), so the
    /// content matches -- except that a field the API sent and this struct
    /// does not model is absent here, and one it omitted appears with its
    /// default.
    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
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
        // Not optional and not a `?`: `build()` panics outright when no crypto
        // provider is installed, and nothing guarantees an earlier call here.
        crate::install_crypto_provider();
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
        // A body that is not the agreed JSON is a failure the operator has
        // to be able to see the request for, exactly like a 500 or a
        // refused connection.
        if let Err(ApiError::Transport(_) | ApiError::Status(_, _) | ApiError::Json(_)) = &result {
            tracing::debug!("{}", request.redacted_json());
        }
        result
    }

    async fn post(&self, request: &CheckRequest) -> Result<CheckResponse, ApiError> {
        let response = self.client.post(&self.url).json(request).send().await?;
        let status = response.status();
        // The Perl logs this on every call (`SMTPProxy/API.pm:16`). It is
        // the only line that says the API answered at all, and with what.
        tracing::debug!(
            "validation call to {} returned {}",
            self.url,
            status.as_u16()
        );
        if !status.is_success() {
            return Err(ApiError::Status(status.as_u16(), status_reason(status)));
        }
        let body = response.text().await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Json(e.to_string()))
    }
}

/// The text logged for a non-2xx status (spec 5.3, Perl: `$tx->result->message`).
/// Hyper discards the server's own HTTP/1.1 reason phrase, so the best we can
/// do for a code we don't recognise is the numeric status rather than an
/// empty `()` in the log line.
fn status_reason(status: reqwest::StatusCode) -> String {
    status
        .canonical_reason()
        .map(str::to_string)
        .unwrap_or_else(|| status.as_u16().to_string())
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

    /// The relay-failure dump is JSON, as the manual (LOGS) promises of every debug
    /// dump, and it carries the API's own field names.
    #[test]
    fn response_json_is_the_dump_format() {
        let response = CheckResponse {
            allow: true,
            reason: None,
            headers: vec![ResponseHeader {
                name: "X".into(),
                value: Some("1".into()),
            }],
            from: Some("o@b.com".into()),
            auth_id: Some("tok".into()),
        };
        assert_eq!(
            response.json(),
            r#"{"allow":true,"reason":null,"headers":[{"name":"X","value":"1"}],"from":"o@b.com","authId":"tok"}"#
        );
    }

    #[test]
    fn debug_hides_the_password() {
        let printed = format!("{:?}", request());
        assert!(printed.contains("*******"), "{printed}");
        assert!(!printed.contains("secret"), "{printed}");
    }

    #[test]
    fn status_reason_falls_back_to_the_numeric_code_when_unrecognised() {
        assert_eq!(
            status_reason(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            "Internal Server Error"
        );
        let non_standard = reqwest::StatusCode::from_u16(599).unwrap();
        assert_eq!(status_reason(non_standard), "599");
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

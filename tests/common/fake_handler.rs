//! A `Handler` whose answers a test scripts in advance, and which records
//! every call. It stands in for the inline callbacks of the Perl tests.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use smtp_proxy::relay::UpstreamVerdict;
use smtp_proxy::server::{BodySink, Handler, HandlerFactory, Rejection};
use smtp_proxy::smtp::params::Param;

#[derive(Default, Debug, Clone)]
pub struct Recorded {
    pub auth: Vec<(String, String, String)>,
    pub mail: Vec<(String, Vec<Param>)>,
    pub rcpt: Vec<(String, Vec<Param>)>,
    pub headers: Vec<String>,
    /// One entry per message that reached `finish`, exactly as the sink was
    /// given it: verbatim body lines, stuffing dot and all, with the line
    /// endings normalised to CRLF. That is what a real sink writes upstream.
    pub bodies: Vec<Vec<u8>>,
    pub resets: usize,
    /// Bumped on entry to `open_body`, before anything it might wait for. A
    /// test that has to act while a message is in flight polls this rather
    /// than sleeping a guessed margin.
    pub message_started: usize,
}

#[derive(Clone)]
pub struct Script {
    pub auth_ok: bool,
    pub mail_error: Option<Rejection>,
    pub rcpt_error: Option<Rejection>,
    /// What `BodySink::finish` answers once it is past the hold and the
    /// delay. An `Err` reaches the client as the upstream's own reply.
    pub message_result: Result<String, Rejection>,
    /// When set, every `BodySink::write` fails with it instead of staging
    /// the chunk -- an upstream that refused or died mid-body.
    pub sink_verdict: Option<UpstreamVerdict>,
    pub dsn: bool,
    pub size_limit: Option<usize>,
    /// Delay before `BodySink::finish` answers, to simulate a slow relay.
    pub message_delay: std::time::Duration,
    /// Holds `BodySink::finish` until the test releases it with
    /// `notify_one`, so a message can be kept provably in flight without
    /// timing anything.
    /// `Notify::notify_one` stores its permit, so releasing it before the
    /// handler gets there is safe.
    pub message_hold: Option<Arc<tokio::sync::Notify>>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            auth_ok: true,
            mail_error: None,
            rcpt_error: None,
            message_result: Ok("queued".into()),
            sink_verdict: None,
            dsn: true,
            size_limit: None,
            message_delay: std::time::Duration::ZERO,
            message_hold: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct ScriptedFactory {
    pub script: Arc<Mutex<Script>>,
    pub recorded: Arc<Mutex<Recorded>>,
}

impl ScriptedFactory {
    pub fn set(&self, f: impl FnOnce(&mut Script)) {
        f(&mut self.script.lock().unwrap());
    }

    pub fn recorded(&self) -> Recorded {
        self.recorded.lock().unwrap().clone()
    }
}

pub struct ScriptedHandler {
    script: Arc<Mutex<Script>>,
    recorded: Arc<Mutex<Recorded>>,
}

impl HandlerFactory for ScriptedFactory {
    type Handler = ScriptedHandler;

    fn create(&self, _client: SocketAddr, _id: &str) -> ScriptedHandler {
        ScriptedHandler {
            script: self.script.clone(),
            recorded: self.recorded.clone(),
        }
    }
}

impl ScriptedHandler {
    fn script(&self) -> Script {
        self.script.lock().unwrap().clone()
    }
}

pub struct ScriptedSink {
    script: Arc<Mutex<Script>>,
    recorded: Arc<Mutex<Recorded>>,
    body: Vec<u8>,
}

impl BodySink for ScriptedSink {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), UpstreamVerdict> {
        if let Some(v) = self.script.lock().unwrap().sink_verdict.clone() {
            return Err(v);
        }
        self.body.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(self) -> Result<String, UpstreamVerdict> {
        let script = self.script.lock().unwrap().clone();
        if let Some(hold) = &script.message_hold {
            hold.notified().await;
        }
        tokio::time::sleep(script.message_delay).await;
        self.recorded.lock().unwrap().bodies.push(self.body);
        script.message_result.map_err(|r| UpstreamVerdict::Replied {
            code: r.code,
            text: r.text,
        })
    }
}

impl Handler for ScriptedHandler {
    type Sink = ScriptedSink;

    async fn auth(&mut self, authzid: &str, authcid: &str, password: &str) -> Result<(), String> {
        self.recorded
            .lock()
            .unwrap()
            .auth
            .push((authzid.into(), authcid.into(), password.into()));
        if self.script().auth_ok {
            Ok(())
        } else {
            Err("nope".into())
        }
    }

    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), Rejection> {
        self.recorded
            .lock()
            .unwrap()
            .mail
            .push((from.into(), params.to_vec()));
        self.script().mail_error.map_or(Ok(()), Err)
    }

    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), Rejection> {
        self.recorded
            .lock()
            .unwrap()
            .rcpt
            .push((to.into(), params.to_vec()));
        self.script().rcpt_error.map_or(Ok(()), Err)
    }

    async fn open_body(&mut self, headers: String) -> Result<ScriptedSink, Rejection> {
        let mut recorded = self.recorded.lock().unwrap();
        recorded.headers.push(headers);
        recorded.message_started += 1;
        drop(recorded);
        Ok(ScriptedSink {
            script: self.script.clone(),
            recorded: self.recorded.clone(),
            body: Vec::new(),
        })
    }

    fn reset(&mut self) {
        self.recorded.lock().unwrap().resets += 1;
    }

    fn dsn_available(&self) -> bool {
        self.script().dsn
    }

    fn size_limit(&self) -> Option<usize> {
        self.script().size_limit
    }
}

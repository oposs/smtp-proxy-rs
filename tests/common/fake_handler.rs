//! A `Handler` whose answers a test scripts in advance, and which records
//! every call. It stands in for the inline callbacks of the Perl tests.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use smtp_proxy::server::{Handler, HandlerFactory, Rejection};
use smtp_proxy::smtp::params::Param;

#[derive(Default, Debug, Clone)]
pub struct Recorded {
    pub auth: Vec<(String, String, String)>,
    pub mail: Vec<(String, Vec<Param>)>,
    pub rcpt: Vec<(String, Vec<Param>)>,
    pub headers: Vec<String>,
    pub bodies: Vec<Vec<u8>>,
    pub resets: usize,
    /// Bumped on entry to `message`, before anything it might wait for. A
    /// test that has to act while a message is in flight polls this rather
    /// than sleeping a guessed margin.
    pub message_started: usize,
}

#[derive(Clone)]
pub struct Script {
    pub auth_ok: bool,
    pub mail_error: Option<Rejection>,
    pub rcpt_error: Option<Rejection>,
    pub message_result: Result<String, Rejection>,
    pub dsn: bool,
    pub size_limit: Option<usize>,
    /// Delay before answering `message`, to simulate a slow relay.
    pub message_delay: std::time::Duration,
    /// Holds `message` until the test releases it with `notify_one`, so a
    /// message can be kept provably in flight without timing anything.
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

impl Handler for ScriptedHandler {
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

    async fn headers(&mut self, headers: String) -> Result<(), String> {
        self.recorded.lock().unwrap().headers.push(headers);
        Ok(())
    }

    async fn message(&mut self, body: Vec<u8>) -> Result<String, Rejection> {
        let script = self.script();
        self.recorded.lock().unwrap().message_started += 1;
        if let Some(hold) = &script.message_hold {
            hold.notified().await;
        }
        tokio::time::sleep(script.message_delay).await;
        self.recorded.lock().unwrap().bodies.push(body);
        script.message_result
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

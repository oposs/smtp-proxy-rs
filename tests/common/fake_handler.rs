//! A `Handler` whose answers a test scripts in advance, and which records
//! every call. It stands in for the inline callbacks of the Perl tests.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use smtp_proxy::server::{Handler, HandlerFactory};
use smtp_proxy::smtp::params::Param;

#[derive(Default, Debug, Clone)]
pub struct Recorded {
    pub auth: Vec<(String, String, String)>,
    pub mail: Vec<(String, Vec<Param>)>,
    pub rcpt: Vec<(String, Vec<Param>)>,
    pub headers: Vec<String>,
    pub bodies: Vec<Vec<u8>>,
    pub resets: usize,
}

#[derive(Clone)]
pub struct Script {
    pub auth_ok: bool,
    pub mail_error: Option<String>,
    pub rcpt_error: Option<String>,
    pub message_result: Result<String, String>,
    pub dsn: bool,
    /// Delay before answering `message`, to simulate a slow relay.
    pub message_delay: std::time::Duration,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            auth_ok: true,
            mail_error: None,
            rcpt_error: None,
            message_result: Ok("queued".into()),
            dsn: true,
            message_delay: std::time::Duration::ZERO,
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

    async fn mail(&mut self, from: &str, params: &[Param]) -> Result<(), String> {
        self.recorded
            .lock()
            .unwrap()
            .mail
            .push((from.into(), params.to_vec()));
        self.script().mail_error.map_or(Ok(()), Err)
    }

    async fn rcpt(&mut self, to: &str, params: &[Param]) -> Result<(), String> {
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

    async fn message(&mut self, body: Vec<u8>) -> Result<String, String> {
        let script = self.script();
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
}

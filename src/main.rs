use std::{collections::HashMap, process::Stdio, sync::Arc, time::Duration};

use anyhow::Result;
use gtk4::{
  glib::{self, ExitCode},
  prelude::*,
};
use gtk4_layer_shell::LayerShell;
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncBufReadExt, AsyncWriteExt},
  sync::{oneshot, RwLock},
  time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zvariant::Type;

const OBJECT_PATH: &str = "/lol/happens/CosmicOsd";

#[zbus::proxy(
  default_service = "org.freedesktop.login1",
  interface = "org.freedesktop.login1.Session",
  default_path = "/org/freedesktop/login1/session/auto"
)]
trait LogindSession {
  #[zbus(property)]
  fn id(&self) -> zbus::Result<String>;
}

#[derive(Serialize, Type)]
pub struct Subject<'a> {
  subject_kind: &'a str,
  subject_details: HashMap<&'a str, zvariant::Value<'a>>,
}

#[zbus::proxy(
  default_service = "org.freedesktop.PolicyKit1",
  interface = "org.freedesktop.PolicyKit1.Authority",
  default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait PolkitAuthority {
  fn register_authentication_agent(
    &self,
    subject: Subject<'_>,
    locale: &str,
    object_path: &str,
  ) -> zbus::Result<()>;

  fn unregister_authentication_agent(
    &self,
    subject: Subject<'_>,
    object_path: &str,
  ) -> zbus::Result<()>;
}

#[derive(Clone, Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
pub enum PolkitError {
  Failed,
  Cancelled,
  NotSupported,
  NotAuthorized,
  CancellationIdNotUnique,
}

impl From<tokio::io::Error> for PolkitError {
  fn from(_: tokio::io::Error) -> Self {
    PolkitError::Failed
  }
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct Identity<'a> {
  identity_kind: &'a str,
  identity_details: HashMap<&'a str, zvariant::Value<'a>>,
}

#[allow(unused)]
enum Event {
  ReadPassword(flume::Sender<String>, CancellationToken),
  ReadFingerprint,
  End,
}

struct AuthenticationAttempt {
  cookie: String,
  token: CancellationToken,
}

struct PolkitAgent {
  sender: flume::Sender<Event>,
  attempt: Arc<RwLock<Option<AuthenticationAttempt>>>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl PolkitAgent {
  async fn begin_authentication(
    &self,
    _action_id: String,
    msg: String,
    _icon_name: String,
    _details: HashMap<String, String>,
    cookie: String,
    identities: Vec<Identity<'_>>,
  ) -> Result<(), PolkitError> {
    info!("Starting authentication attempt ({msg})");

    let existing_attempt = self.attempt.read().await.is_some();

    if existing_attempt {
      error!("Attempt already in progress");
      return Err(PolkitError::Failed);
    }

    let Some(username) = select_username_from_identities(&identities) else {
      error!("Unable to select user from identities");
      return Err(PolkitError::Failed);
    };

    let token = CancellationToken::new();
    {
      let mut attempt = self.attempt.write().await;
      let cookie = cookie.clone();
      let token = token.clone();
      *attempt = Some(AuthenticationAttempt { cookie, token });
    }

    let result = self.authenticate(cookie, username, token).await;
    self.sender.send_async(Event::End).await.expect("send end");

    {
      let mut attempt = self.attempt.write().await;
      *attempt = None;
    }

    debug!("Helper process shut down ({result:?})");
    info!("Authentication attempt complete");
    result
  }

  async fn cancel_authentication(&self, cookie: String) -> Result<(), PolkitError> {
    info!("Canceling authentication");
    let attempt = self.attempt.read().await;
    let Some(attempt) = attempt.as_ref() else {
      error!("Attempt not in progress");
      return Ok(());
    };

    if attempt.cookie != cookie {
      error!("Attempt cookie mismatch");
      return Ok(());
    }

    attempt.token.cancel();

    Ok(())
  }
}

impl PolkitAgent {
  async fn authenticate(
    &self,
    cookie: String,
    username: String,
    token: CancellationToken,
  ) -> Result<(), PolkitError> {
    let mut process = tokio::process::Command::new("polkit-agent-helper-1")
      .arg(&username)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::null())
      .spawn()
      .unwrap();

    let mut stdin = process.stdin.take().expect("take stdin");
    let stdout = process.stdout.take().expect("take stdout");

    if let Err(err) = stdin.write_all(cookie.as_bytes()).await {
      error!("Failed to write cookie to agent helper: {err}");
      return Err(PolkitError::Failed);
    };

    if let Err(err) = stdin.write_all(b"\n").await {
      error!("Failed to write newline to agent helper: {err}");
      return Err(PolkitError::Failed);
    };

    let (password_tx, password_rx) = flume::unbounded::<String>();

    let mut reader = tokio::io::BufReader::new(stdout).lines();
    loop {
      let (token, password_tx) = (token.clone(), password_tx.clone());
      let should_continue = tokio::select! {
        line = reader.next_line() => self.handle_helper_line(line, token, password_tx).await?,
        Ok(pw) = password_rx.recv_async() => self.handle_password(pw, &mut stdin).await?,
        _ = token.cancelled() => return Err(PolkitError::Cancelled),
      };

      if !should_continue {
        break;
      }
    }

    let result = timeout(Duration::from_secs(1), process.wait()).await;
    if result.is_err() {
      warn!("Killing helper process after 1s");
      process.kill().await?;
    }

    Ok(())
  }

  async fn handle_password(
    &self,
    password: String,
    stdin: &mut tokio::process::ChildStdin,
  ) -> Result<bool, PolkitError> {
    stdin.write_all(password.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    Ok(true)
  }

  async fn handle_helper_line(
    &self,
    line: Result<Option<String>, std::io::Error>,
    token: CancellationToken,
    password_tx: flume::Sender<String>,
  ) -> Result<bool, PolkitError> {
    let line = line.map_err(|err| {
      error!("Failed to read line from agent helper: {err}");
      PolkitError::Failed
    })?;

    let Some(line) = line else {
      return Ok(false);
    };

    debug!("Agent helper response: {line}");

    let line = line.trim();
    let (prefix, pam_msg) = line.split_once(' ').unwrap_or((line, ""));

    match prefix {
      "PAM_PROMPT_ECHO_OFF" => {
        // We just assume it's a password prompt
        debug!("PAM blind prompt: {pam_msg}");
        self
          .sender
          .send_async(Event::ReadPassword(password_tx, token))
          .await
          .map_err(|_| {
            error!("Failed to send password prompt");
            PolkitError::Failed
          })?;

        Ok(true)
      }
      "PAM_PROMPT_ECHO_ON" => {
        error!("Unexpected PAM echo prompt: {pam_msg}");
        Err(PolkitError::Failed)
      }
      "PAM_ERROR_MSG" => Ok(true),
      "PAM_TEXT_INFO" => Ok(true),
      "SUCCESS" => Ok(false),
      "FAILURE" => Err(PolkitError::Failed),
      _ => {
        error!("Unknown line '{line}' from agent helper");
        Ok(true)
      }
    }
  }
}

fn main() -> Result<ExitCode> {
  tracing_subscriber::fmt::init();

  let app = gtk4::Application::builder()
    .application_id("lol.happens.pkagent")
    .flags(gtk4::gio::ApplicationFlags::default() | gtk4::gio::ApplicationFlags::NON_UNIQUE)
    .build();

  let (ev_tx, ev_rx) = flume::unbounded();
  let (rt_shutdown_tx, rt_shutdown_rx) = oneshot::channel::<()>();

  let app_token = CancellationToken::new();
  let app_token_rt = app_token.clone();
  let rt_thread = std::thread::spawn(move || {
    let rt = tokio::runtime::Builder::new_multi_thread()
      .enable_all()
      .build()
      .expect("build tokio runtime");

    rt.block_on(async {
      let connection = match zbus::Connection::system().await {
        Ok(connection) => connection,
        Err(err) => {
          error!("Failed to connect to system bus: {err}");
          app_token_rt.cancel();
          return;
        }
      };

      if let Err(err) = register_agent(&connection, ev_tx).await {
        error!("Failed to register agent: {err}");
        app_token_rt.cancel();
        return;
      }

      rt_shutdown_rx.await.expect("wait for shutdown signal");
    });
  });

  let _guard = app.hold();
  app.connect_activate(move |app| {
    let (ev_rx, app, app_token) = (ev_rx.clone(), app.clone(), app_token.clone());

    let app_cancel = app.clone();
    glib::spawn_future_local(async move {
      app_token.cancelled().await;
      app_cancel.quit();
    });

    glib::spawn_future_local(async move {
      let mut dialog: Option<gtk4::ApplicationWindow> = None;

      while let Ok(ev) = ev_rx.recv_async().await {
        match ev {
          Event::ReadPassword(tx, token) => {
            let window = dialog.get_or_insert_with(|| create_window(&app));
            show_password_prompt(window, tx, token);
            window.present();
          }
          Event::ReadFingerprint => {
            let window = dialog.get_or_insert_with(|| create_window(&app));
            show_fingerprint_prompt(window);
            window.present();
          }
          Event::End => {
            if let Some(dialog) = dialog.take() {
              dialog.destroy();
            }
          }
        }
      }
    });
  });

  let code = app.run();
  let _ = rt_shutdown_tx.send(());
  rt_thread.join().expect("join async runtime thread");

  Ok(code)
}

fn create_window(app: &gtk4::Application) -> gtk4::ApplicationWindow {
  let window = gtk4::ApplicationWindow::builder().application(app).build();

  window.init_layer_shell();
  window.set_keyboard_mode(gtk4_layer_shell::KeyboardMode::OnDemand);
  window.set_layer(gtk4_layer_shell::Layer::Overlay);

  window
}

fn show_password_prompt(
  window: &gtk4::ApplicationWindow,
  tx: flume::Sender<String>,
  token: CancellationToken,
) {
  let cancel_button = gtk4::Button::builder().label("Cancel").build();
  cancel_button.connect_clicked(move |_| {
    token.cancel();
  });

  let input = gtk4::PasswordEntry::builder()
    .placeholder_text("password")
    .build();

  input.connect_activate(move |input| {
    tx.send(input.text().to_string()).unwrap_or_else(|err| {
      error!("Failed to send password action: {err}");
    });
  });

  let bbox = gtk4::Box::builder()
    .orientation(gtk4::Orientation::Vertical)
    .spacing(10)
    .build();

  bbox.append(&input);
  bbox.append(&cancel_button);

  window.set_child(Some(&bbox));
  input.grab_focus();
}

fn show_fingerprint_prompt(_window: &gtk4::ApplicationWindow) {}

async fn register_agent(connection: &zbus::Connection, tx: flume::Sender<Event>) -> Result<()> {
  let agent = PolkitAgent {
    sender: tx,
    attempt: Arc::new(RwLock::new(None)),
  };

  connection.object_server().at(OBJECT_PATH, agent).await?;

  let session = LogindSessionProxy::new(connection).await?;
  let session_id = session.id().await?;

  let mut subject_details = HashMap::new();
  subject_details.insert("session-id", session_id.into());
  let subject = Subject {
    subject_kind: "unix-session",
    subject_details,
  };

  let authority = PolkitAuthorityProxy::new(connection).await?;
  authority
    .register_authentication_agent(subject, "en_US", OBJECT_PATH)
    .await?;

  info!("Agent registered");
  Ok(())
}

// from cosmic-usd
fn select_username_from_identities(identities: &[Identity]) -> Option<String> {
  let mut uids = Vec::new();
  for ident in identities {
    if ident.identity_kind == "unix-user" {
      if let Some(zvariant::Value::U32(uid)) = ident.identity_details.get("uid") {
        uids.push(*uid);
      }
    }
    // `unix-group` is apparently a thing too, but Gnome Shell doesn't seem to handle it...
  }

  // Like Gnome Shell, try own uid, then root, then first UID in `identities`
  let uid = *uids
    .iter()
    .find(|uid| **uid == uzers::get_current_uid())
    .or(uids.iter().find(|uid| **uid == 0))
    .or_else(|| uids.first())?;

  let user = uzers::get_user_by_uid(uid)?;
  Some(user.name().to_str()?.to_string())
}

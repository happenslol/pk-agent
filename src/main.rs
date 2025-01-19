use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;
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

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct Identity<'a> {
  identity_kind: &'a str,
  identity_details: HashMap<&'a str, zvariant::Value<'a>>,
}

struct PolkitAgent {
  sender: flume::Sender<()>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl PolkitAgent {
  async fn begin_authentication(
    &self,
    action_id: String,
    msg: String,
    icon_name: String,
    details: HashMap<String, String>,
    cookie: String,
    identities: Vec<Identity<'_>>,
  ) -> Result<(), PolkitError> {
    info!(
      action_id = action_id,
      msg = msg,
      icon_name = icon_name,
      details = ?details,
      cookie = cookie,
      identities = ?identities,
      "begin_authentication",
    );
    Ok(())
  }

  async fn cancel_authentication(&self, cookie: String) -> Result<(), PolkitError> {
    info!("begin_authentication");
    Ok(())
  }
}

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt::init();

  let connection = zbus::Connection::system().await.unwrap();
  let (tx, rx) = flume::unbounded();
  register_agent(&connection, tx).await?;

  while let Ok(()) = rx.recv_async().await {
    info!("received");
  }

  Ok(())
}

async fn register_agent(connection: &zbus::Connection, tx: flume::Sender<()>) -> Result<()> {
  let agent = PolkitAgent { sender: tx };
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

  info!("registered agent");
  Ok(())
}

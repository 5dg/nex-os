//! Bounded PostgreSQL connections. A permit lives until its actual connection
//! task terminates, including a cancelled RPC's pending rollback/query work.
use crate::{profile::Profile, trust::Trust};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio_postgres::{
    Client, Config, NoTls,
    config::{Host, SslMode},
};
use tonic::Status;

pub(crate) const CONNECTION_CAPACITY: usize = 8;

pub struct StateStore {
    config: Config,
    profile: Profile,
    tls: Option<rustls::ClientConfig>,
    permits: Arc<Semaphore>,
}
fn unavailable() -> Status {
    Status::unavailable("bounded state dependency unavailable")
}
pub fn configuration(profile: Profile, url: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config: Config = if profile == Profile::Qualification {
        let mut parsed = reqwest::Url::parse(url)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql")
            || parsed.host_str() != Some("postgres")
        {
            return Err("qualification requires the postgres DNS identity".into());
        }
        let parameters: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if parameters
            .iter()
            .filter(|(k, _)| k == "sslmode")
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            != ["verify-full"]
        {
            return Err("qualification requires explicit sslmode=verify-full".into());
        }
        // tokio-postgres only parses disable/prefer/require. The external
        // verify-full contract maps to required TLS PLUS a mandatory Rustls
        // pinned-CA/DNS verifier; no require-only operator mode is accepted.
        parsed
            .query_pairs_mut()
            .clear()
            .extend_pairs(parameters.iter().map(|(k, v)| {
                (
                    k.as_str(),
                    if k == "sslmode" {
                        "require"
                    } else {
                        v.as_str()
                    },
                )
            }));
        parsed.as_str().parse()?
    } else {
        url.parse()?
    };
    if profile == Profile::Qualification {
        if config.get_ssl_mode() != SslMode::Require
            || !matches!(config.get_hosts(),[Host::Tcp(name)] if name=="postgres")
        {
            return Err("verified PostgreSQL identity required".into());
        }
    }
    config.connect_timeout(Duration::from_secs(3));
    Ok(config)
}
impl StateStore {
    pub fn new(profile: Profile, url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = configuration(profile, url)?;
        let tls = if profile == Profile::Qualification {
            Some(Trust::database_tls()?)
        } else {
            None
        };
        Ok(Self {
            config,
            profile,
            tls,
            permits: Arc::new(Semaphore::new(CONNECTION_CAPACITY)),
        })
    }
    pub(crate) fn admission(&self) -> Arc<Semaphore> {
        self.permits.clone()
    }
    pub async fn connect(&self) -> Result<Client, Status> {
        let permit =
            tokio::time::timeout(Duration::from_secs(3), self.permits.clone().acquire_owned())
                .await
                .map_err(|_| unavailable())?
                .map_err(|_| unavailable())?;
        let client = if self.profile == Profile::Qualification {
            let connector = tokio_postgres_rustls::MakeRustlsConnect::new(
                self.tls.clone().ok_or_else(unavailable)?,
            );
            let (client, connection) =
                tokio::time::timeout(Duration::from_secs(3), self.config.connect(connector))
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(Duration::from_secs(20), connection).await;
            });
            client
        } else {
            let (client, connection) =
                tokio::time::timeout(Duration::from_secs(3), self.config.connect(NoTls))
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(Duration::from_secs(20), connection).await;
            });
            client
        };
        tokio::time::timeout(Duration::from_secs(3),client.batch_execute("SET statement_timeout='3s'; SET lock_timeout='2s'; SET idle_in_transaction_session_timeout='5s'" )).await.map_err(|_|unavailable())?.map_err(|_|unavailable())?;
        Ok(client)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualification_never_downgrades_database_verification() {
        for url in [
            "postgres://postgres/nex?sslmode=disable",
            "postgres://postgres/nex?sslmode=require",
            "postgres://localhost/nex?sslmode=verify-full",
            "postgres://postgres/nex",
            "postgres://postgres/nex?sslmode=verify-full&sslmode=require",
            "host=postgres sslmode=require",
        ] {
            assert!(configuration(Profile::Qualification, url).is_err(), "{url}");
        }
        let config = configuration(
            Profile::Qualification,
            "postgres://postgres/nex?sslmode=verify-full&hostaddr=127.0.0.1",
        )
        .unwrap();
        assert_eq!(config.get_ssl_mode(), SslMode::Require);
        assert!(matches!(config.get_hosts(),[Host::Tcp(name)]if name=="postgres"));
    }
}

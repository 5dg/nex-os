//! Private test-PKI transport, deliberately not a production/FIPS provider.
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};
use tonic::{
    Request, Status,
    transport::server::{TcpConnectInfo, TlsConnectInfo},
};
use x509_parser::{extensions::GeneralName, prelude::*};

pub const PREFIX: &str = "spiffe://nex.local/service/";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Workspace,
    Control,
    Guard,
    Model,
    Export,
    Evidence,
    Worker,
    Opa,
    Oidc,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Control => "control",
            Self::Guard => "guard",
            Self::Model => "model",
            Self::Export => "export",
            Self::Evidence => "evidence",
            Self::Worker => "worker",
            Self::Opa => "opa",
            Self::Oidc => "oidc",
        }
    }
    pub fn uri(self) -> String {
        format!("{PREFIX}{}", self.name())
    }
    fn from_uri(value: &str) -> Option<Self> {
        [
            Self::Workspace,
            Self::Control,
            Self::Guard,
            Self::Model,
            Self::Export,
            Self::Evidence,
            Self::Worker,
            Self::Opa,
            Self::Oidc,
        ]
        .into_iter()
        .find(|role| role.uri() == value)
    }
}
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub role: Role,
    certificates: Option<Arc<Vec<CertificateDer<'static>>>>,
}
impl PeerIdentity {
    pub fn development(role: Role) -> Self {
        Self {
            role,
            certificates: None,
        }
    }

    // Only a peer obtained from verified mTLS has certificate material. This
    // fingerprint is an input to independently trusted instance verification,
    // not by itself an authorization or a long-lived identity.
    pub fn certificate_sha256(&self) -> Option<[u8; 32]> {
        self.certificates
            .as_ref()?
            .first()
            .map(|certificate| Sha256::digest(certificate.as_ref()).into())
    }
}
type ChainCache = Arc<Mutex<BTreeMap<Vec<u8>, Arc<Vec<CertificateDer<'static>>>>>>;
#[derive(Clone, Debug)]
pub(crate) struct HttpPeer {
    chain: Arc<Vec<CertificateDer<'static>>>,
    name: ServerName<'static>,
    role: Role,
}

pub struct Trust {
    ca: Vec<CertificateDer<'static>>,
    certificate: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    server_chains: ChainCache,
}
impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trust").finish_non_exhaustive()
    }
}
fn denied() -> Status {
    Status::unauthenticated("verified current workload identity required")
}
fn certificate_role(der: &CertificateDer<'_>) -> Result<Role, Box<dyn std::error::Error>> {
    let (remaining, certificate) =
        parse_x509_certificate(der.as_ref()).map_err(|_| "invalid identity certificate")?;
    if !remaining.is_empty() || !certificate.validity().is_valid() {
        return Err("identity certificate is not currently valid".into());
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| "invalid identity SAN")?
        .ok_or("identity URI SAN required")?;
    let identities: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|v| {
            if let GeneralName::URI(uri) = v {
                Some(*uri)
            } else {
                None
            }
        })
        .collect();
    if identities.len() != 1 {
        return Err("exactly one service URI SAN required".into());
    }
    Role::from_uri(identities[0]).ok_or_else(|| "unknown service URI SAN".into())
}
fn roots_at(
    certs: &[CertificateDer<'static>],
) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for der in certs {
        let (remaining, certificate) =
            parse_x509_certificate(der.as_ref()).map_err(|_| "invalid trust root")?;
        if !remaining.is_empty() || !certificate.is_ca() {
            return Err("valid CA trust root required".into());
        }
        // During rotation an expired old root cannot authenticate a peer; a
        // still-valid new root in the same explicit bundle remains usable.
        if certificate.validity().is_valid() {
            roots.add(der.clone())?;
        }
    }
    if roots.is_empty() {
        return Err("no currently valid pinned trust roots".into());
    }
    Ok(roots)
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, rustls::SupportedCipherSuite::Tls13(_)));
    Arc::new(provider)
}
fn read_certificates(
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let certs = CertificateDer::pem_slice_iter(&bytes).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("certificate PEM required".into());
    }
    Ok(certs)
}
fn read_private_key(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    // Retain the first supported PKCS#1, PKCS#8 or SEC1 key. Parsing its PEM
    // envelope does not validate DER or its match to the workload certificate;
    // server_config still performs those checks before the process can start.
    Ok(PrivateKeyDer::from_pem_slice(&fs::read(path)?)?)
}
impl Trust {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let ca = read_certificates(&std::env::var("NEX_TLS_CA_FILE")?)?;
        let certificate = read_certificates(&std::env::var("NEX_TLS_CERT_FILE")?)?;
        let key = read_private_key(&std::env::var("NEX_TLS_KEY_FILE")?)?;
        let trust = Self {
            ca,
            certificate,
            key,
            server_chains: Arc::new(Mutex::new(BTreeMap::new())),
        };
        trust
            .check_own()
            .map_err(|_| "invalid Guard workload identity")?;
        let _ = trust.server_config()?;
        Ok(trust)
    }
    fn client_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, Box<dyn std::error::Error>> {
        Ok(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots_at(&self.ca)?), provider())
                .build()?,
        )
    }
    fn check_certificates(
        &self,
        certs: &[CertificateDer<'static>],
        roles: &[Role],
    ) -> Result<Role, Status> {
        let leaf = certs.first().ok_or_else(denied)?;
        let role = certificate_role(leaf).map_err(|_| denied())?;
        if !roles.contains(&role) {
            return Err(Status::permission_denied(
                "workload role does not permit this endpoint",
            ));
        }
        self.client_verifier()
            .map_err(|_| denied())?
            .verify_client_cert(leaf, &certs[1..], UnixTime::now())
            .map_err(|_| denied())?;
        Ok(role)
    }
    pub fn check_own(&self) -> Result<(), Status> {
        self.check_certificates(&self.certificate, &[Role::Guard])
            .map(|_| ())
    }
    pub fn authenticate<T>(&self, r: &Request<T>, roles: &[Role]) -> Result<PeerIdentity, Status> {
        self.check_own()?;
        let certs = r
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|v| v.peer_certs())
            .ok_or_else(denied)?;
        let role = self.check_certificates(&certs, roles)?;
        Ok(PeerIdentity {
            role,
            certificates: Some(certs),
        })
    }
    pub fn check_current(&self, peer: &PeerIdentity) -> Result<(), Status> {
        self.check_own()?;
        self.check_certificates(peer.certificates.as_ref().ok_or_else(denied)?, &[peer.role])
            .map(|_| ())
    }
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(self.client_verifier()?)
            .with_single_cert(self.certificate.clone(), self.key.clone_key())?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Arc::new(config))
    }
    pub fn http_client(&self, peer: Role) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
        self.check_own()
            .map_err(|_| "Guard identity is not current")?;
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots_at(&self.ca)?)
            .with_client_auth_cert(self.certificate.clone(), self.key.clone_key())?;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(UriServerVerifier {
                ca: self.ca.clone(),
                role: Some(peer),
                chains: Some(self.server_chains.clone()),
            }));
        Ok(reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(0)
            .http1_only()
            .tls_info(true)
            .build()?)
    }
    pub(crate) fn response_peer(
        &self,
        response: &reqwest::Response,
        role: Role,
    ) -> Result<HttpPeer, Status> {
        self.check_own()?;
        let leaf = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|v| v.peer_certificate())
            .ok_or_else(denied)?;
        let key = Sha256::digest(leaf).to_vec();
        let chain = self
            .server_chains
            .lock()
            .map_err(|_| denied())?
            .get(&key)
            .cloned()
            .ok_or_else(denied)?;
        if chain.first().map(|v| v.as_ref()) != Some(leaf) {
            return Err(denied());
        }
        let name = ServerName::try_from(response.url().host_str().ok_or_else(denied)?.to_owned())
            .map_err(|_| denied())?;
        Ok(HttpPeer { chain, name, role })
    }
    pub(crate) fn check_http_peer(&self, peer: &HttpPeer) -> Result<(), Status> {
        self.check_own()?;
        let verifier = UriServerVerifier {
            ca: self.ca.clone(),
            role: Some(peer.role),
            chains: None,
        };
        verifier
            .verify_server_cert(
                peer.chain.first().ok_or_else(denied)?,
                &peer.chain[1..],
                &peer.name,
                &[],
                UnixTime::now(),
            )
            .map_err(|_| Status::unavailable("downstream workload identity is no longer valid"))?;
        Ok(())
    }
    pub fn database_tls() -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let ca = read_certificates(&std::env::var("NEX_DB_CA_FILE")?)?;
        // PostgreSQL is server-authenticated TLS with its DNS name, not a
        // workload RPC. No client certificate or insecure verifier is used.
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots_at(&ca)?)
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(UriServerVerifier {
                ca,
                role: None,
                chains: None,
            }));
        Ok(config)
    }
}

#[cfg(test)]
mod pem_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(contents: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "nex-pem-parser-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            // Refuse stale or redirected fixtures instead of replacing them.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
            Self(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn pem(label: &str, body: &str) -> String {
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    #[test]
    fn certificate_bundle_preserves_chain_order_and_rejects_malformed_suffix() {
        let bundle =
            pem("CERTIFICATE", "AQID") + &pem("PUBLIC KEY", "BAUG") + &pem("CERTIFICATE", "BwgJ");
        let file = Fixture::new(&bundle);
        let certs = read_certificates(file.path()).unwrap();
        assert_eq!(
            certs.iter().map(|cert| cert.as_ref()).collect::<Vec<_>>(),
            vec![&[1, 2, 3][..], &[7, 8, 9][..]]
        );
        // Envelope decoding must never turn arbitrary DER into a trust root.
        assert!(roots_at(&certs).is_err());
        let broken = Fixture::new(&(bundle + &pem("CERTIFICATE", "!not-base64!")));
        assert!(read_certificates(broken.path()).is_err());
        let empty = Fixture::new(&pem("PUBLIC KEY", "AQID"));
        assert!(read_certificates(empty.path()).is_err());
    }

    #[test]
    fn private_key_formats_and_first_key_selection_remain_compatible() {
        for label in ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"] {
            let file = Fixture::new(
                &(pem("CERTIFICATE", "BAUG") + &pem(label, "AQID") + &pem("PRIVATE KEY", "BwgJ")),
            );
            let key = read_private_key(file.path()).unwrap();
            assert_eq!(key.secret_der(), &[1, 2, 3]);
            assert!(matches!(
                (&key, label),
                (PrivateKeyDer::Pkcs1(_), "RSA PRIVATE KEY")
                    | (PrivateKeyDer::Pkcs8(_), "PRIVATE KEY")
                    | (PrivateKeyDer::Sec1(_), "EC PRIVATE KEY")
            ));
            // The existing provider rejects syntactically decoded but invalid
            // key material before with_single_cert can establish server identity.
            assert!(provider().key_provider.load_private_key(key).is_err());
        }
    }

    #[test]
    fn missing_truncated_mismatched_and_invalid_base64_keys_fail_closed() {
        for contents in [
            String::new(),
            pem("CERTIFICATE", "AQID"),
            pem("ENCRYPTED PRIVATE KEY", "AQID"),
            pem("PRIVATE KEY", "!bad-base64!"),
            "-----BEGIN PRIVATE KEY-----\nAQID\n".into(),
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END CERTIFICATE-----\n".into(),
        ] {
            let file = Fixture::new(&contents);
            assert!(read_private_key(file.path()).is_err());
        }
    }
}
#[derive(Debug)]
struct UriServerVerifier {
    ca: Vec<CertificateDer<'static>>,
    role: Option<Role>,
    chains: Option<ChainCache>,
}
impl UriServerVerifier {
    fn inner(&self) -> Result<Arc<WebPkiServerVerifier>, rustls::Error> {
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(
                roots_at(&self.ca).map_err(|_| {
                    rustls::Error::General("pinned roots expired or invalid".into())
                })?,
            ),
            provider(),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))
    }
}
impl ServerCertVerifier for UriServerVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner()?
            .verify_server_cert(leaf, intermediates, name, ocsp, now)?;
        if self.role.is_some() && certificate_role(leaf).ok() != self.role {
            return Err(rustls::Error::General("unexpected service URI SAN".into()));
        }
        if let Some(cache) = &self.chains {
            let total = leaf.len() + intermediates.iter().map(|v| v.len()).sum::<usize>();
            if intermediates.len() > 7 || total > 64 * 1024 {
                return Err(rustls::Error::General(
                    "bounded certificate chain required".into(),
                ));
            }
            let mut chain = vec![leaf.clone().into_owned()];
            chain.extend(intermediates.iter().map(|v| v.clone().into_owned()));
            let mut cache = cache.lock().map_err(|_| {
                rustls::Error::General("verified identity cache unavailable".into())
            })?;
            if cache.len() >= 32 {
                cache.pop_first();
            }
            cache.insert(Sha256::digest(leaf.as_ref()).to_vec(), Arc::new(chain));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner()?.verify_tls12_signature(message, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner()?.verify_tls13_signature(message, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Tonic's convenience TLS config lacks a protocol-version setting. This bounded
/// incoming adapter uses an explicit TLS1.3 config and preserves verified peer
/// certificates in Tonic's TlsConnectInfo; no header can create that extension.
pub async fn incoming(
    address: std::net::SocketAddr,
    trust: Arc<Trust>,
    shutdown: crate::Shutdown,
) -> Result<
    tokio_stream::wrappers::ReceiverStream<
        Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
    >,
    Box<dyn std::error::Error>,
> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(trust.server_config()?);
    let (sender, receiver) = tokio::sync::mpsc::channel(32);
    let handshakes = Arc::new(tokio::sync::Semaphore::new(32));
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                _ = shutdown.started() => break,
                _ = sender.closed() => break,
                result = listener.accept() => result,
            };
            let (stream, _) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(1), sender.send(Err(error))).await;
                    break;
                }
            };
            let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                continue;
            };
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let accepted = tokio::select! {
                    biased;
                    _ = shutdown.started() => return,
                    _ = sender.closed() => return,
                    result = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(stream)) => result,
                };
                if let Ok(Ok(stream)) = accepted {
                    tokio::select! {
                        biased;
                        _ = shutdown.started() => {},
                        _ = sender.closed() => {},
                        _ = tokio::time::timeout(Duration::from_secs(1), sender.send(Ok(stream))) => {},
                    }
                }
            });
        }
    });
    Ok(tokio_stream::wrappers::ReceiverStream::new(receiver))
}

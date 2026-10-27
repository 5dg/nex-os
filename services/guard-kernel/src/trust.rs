//! Private test-PKI transport, deliberately not a production/FIPS provider.
use std::{fs, io::Cursor, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, SignatureScheme,
    client::{WebPkiServerVerifier, danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use tonic::{Request, Status, transport::server::{TcpConnectInfo, TlsConnectInfo}};
use x509_parser::{prelude::*, extensions::GeneralName};

pub const PREFIX: &str = "spiffe://nex.local/service/";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Workspace, Control, Guard, Model, Export, Evidence, Worker, Opa, Oidc }
impl Role {
    pub fn name(self) -> &'static str { match self {
        Self::Workspace=>"workspace",Self::Control=>"control",Self::Guard=>"guard",Self::Model=>"model",Self::Export=>"export",Self::Evidence=>"evidence",Self::Worker=>"worker",Self::Opa=>"opa",Self::Oidc=>"oidc"
    }}
    pub fn uri(self) -> String {format!("{PREFIX}{}",self.name())}
    fn from_uri(value:&str)->Option<Self>{
        [Self::Workspace,Self::Control,Self::Guard,Self::Model,Self::Export,Self::Evidence,Self::Worker,Self::Opa,Self::Oidc].into_iter().find(|role|role.uri()==value)
    }
}
#[derive(Clone, Debug)]
pub struct PeerIdentity { pub role:Role, certificates:Option<Arc<Vec<CertificateDer<'static>>>> }
impl PeerIdentity {pub fn development(role:Role)->Self{Self{role,certificates:None}}}
#[derive(Debug)]
pub struct Trust {
    ca:Vec<CertificateDer<'static>>,
    certificate:Vec<CertificateDer<'static>>,
    key:PrivateKeyDer<'static>,
}
fn denied()->Status{Status::unauthenticated("verified current workload identity required")}
fn certificate_role(der:&CertificateDer<'_>)->Result<Role,Box<dyn std::error::Error>>{
    let (remaining,certificate)=parse_x509_certificate(der.as_ref()).map_err(|_|"invalid identity certificate")?;
    if !remaining.is_empty() || !certificate.validity().is_valid(){return Err("identity certificate is not currently valid".into());}
    let san=certificate.subject_alternative_name().map_err(|_|"invalid identity SAN")?.ok_or("identity URI SAN required")?;
    let identities:Vec<&str>=san.value.general_names.iter().filter_map(|v|if let GeneralName::URI(uri)=v{Some(*uri)}else{None}).collect();
    if identities.len()!=1 {return Err("exactly one service URI SAN required".into());}
    Role::from_uri(identities[0]).ok_or_else(||"unknown service URI SAN".into())
}
fn roots_at(certs:&[CertificateDer<'static>])->Result<RootCertStore,Box<dyn std::error::Error>>{
    let mut roots=RootCertStore::empty();
    for der in certs {
        let (remaining,certificate)=parse_x509_certificate(der.as_ref()).map_err(|_|"invalid trust root")?;
        if !remaining.is_empty(){return Err("invalid trust root encoding".into());}
        // During rotation an expired old root cannot authenticate a peer; a
        // still-valid new root in the same explicit bundle remains usable.
        if certificate.validity().is_valid(){ roots.add(der.clone())?; }
    }
    if roots.is_empty(){return Err("no currently valid pinned trust roots".into());}
    Ok(roots)
}
fn provider()->Arc<rustls::crypto::CryptoProvider>{
    let mut provider=rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite|matches!(suite,rustls::SupportedCipherSuite::Tls13(_)));
    Arc::new(provider)
}
fn read_certificates(path:&str)->Result<Vec<CertificateDer<'static>>,Box<dyn std::error::Error>>{
    let bytes=fs::read(path)?;
    let certs=rustls_pemfile::certs(&mut Cursor::new(bytes)).collect::<Result<Vec<_>,_>>()?;
    if certs.is_empty(){return Err("certificate PEM required".into());}Ok(certs)
}
impl Trust {
    pub fn load()->Result<Self,Box<dyn std::error::Error>>{
        let ca=read_certificates(&std::env::var("NEX_TLS_CA_FILE")?)?;
        let certificate=read_certificates(&std::env::var("NEX_TLS_CERT_FILE")?)?;
        let key=rustls_pemfile::private_key(&mut Cursor::new(fs::read(std::env::var("NEX_TLS_KEY_FILE")?)?))?.ok_or("private key PEM required")?;
        let trust=Self{ca,certificate,key};
        trust.check_own().map_err(|_|"invalid Guard workload identity")?;
        let _=trust.server_config()?;
        Ok(trust)
    }
    fn client_verifier(&self)->Result<Arc<dyn ClientCertVerifier>,Box<dyn std::error::Error>>{
        Ok(WebPkiClientVerifier::builder_with_provider(Arc::new(roots_at(&self.ca)?),provider()).build()?)
    }
    fn check_certificates(&self,certs:&[CertificateDer<'static>],roles:&[Role])->Result<Role,Status>{
        let leaf=certs.first().ok_or_else(denied)?;
        let role=certificate_role(leaf).map_err(|_|denied())?;
        if !roles.contains(&role){return Err(Status::permission_denied("workload role does not permit this endpoint"));}
        self.client_verifier().map_err(|_|denied())?.verify_client_cert(leaf,&certs[1..],UnixTime::now()).map_err(|_|denied())?;
        Ok(role)
    }
    pub fn check_own(&self)->Result<(),Status>{self.check_certificates(&self.certificate,&[Role::Guard]).map(|_|())}
    pub fn authenticate<T>(&self,r:&Request<T>,roles:&[Role])->Result<PeerIdentity,Status>{
        self.check_own()?;
        let certs=r.extensions().get::<TlsConnectInfo<TcpConnectInfo>>().and_then(|v|v.peer_certs()).ok_or_else(denied)?;
        let role=self.check_certificates(&certs,roles)?;
        Ok(PeerIdentity{role,certificates:Some(certs)})
    }
    pub fn check_current(&self,peer:&PeerIdentity)->Result<(),Status>{
        self.check_own()?;
        self.check_certificates(peer.certificates.as_ref().ok_or_else(denied)?,&[peer.role]).map(|_|())
    }
    pub fn server_config(&self)->Result<Arc<ServerConfig>,Box<dyn std::error::Error>>{
        let mut config=ServerConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(self.client_verifier()?).with_single_cert(self.certificate.clone(),self.key.clone_key())?;
        config.alpn_protocols=vec![b"h2".to_vec()];
        Ok(Arc::new(config))
    }
    pub fn http_client(&self,peer:Role)->Result<reqwest::Client,Box<dyn std::error::Error>>{
        self.check_own().map_err(|_|"Guard identity is not current")?;
        let mut config=ClientConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots_at(&self.ca)?).with_client_auth_cert(self.certificate.clone(),self.key.clone_key())?;
        config.dangerous().set_certificate_verifier(Arc::new(UriServerVerifier{ca:self.ca.clone(),role:Some(peer)}));
        Ok(reqwest::Client::builder().use_preconfigured_tls(config).https_only(true).redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(3)).pool_max_idle_per_host(0).http1_only().build()?)
    }
    pub fn database_tls()->Result<ClientConfig,Box<dyn std::error::Error>>{
        let ca=read_certificates(&std::env::var("NEX_DB_CA_FILE")?)?;
        // PostgreSQL is server-authenticated TLS with its DNS name, not a
        // workload RPC. No client certificate or insecure verifier is used.
        let mut config=ClientConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots_at(&ca)?).with_no_client_auth();
        config.dangerous().set_certificate_verifier(Arc::new(UriServerVerifier{ca,role:None}));
        Ok(config)
    }
}
#[derive(Debug)]
struct UriServerVerifier {ca:Vec<CertificateDer<'static>>,role:Option<Role>}
impl UriServerVerifier {
    fn inner(&self)->Result<Arc<WebPkiServerVerifier>,rustls::Error>{
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots_at(&self.ca).map_err(|_|rustls::Error::General("pinned roots expired or invalid".into()))?),provider()).build().map_err(|e|rustls::Error::General(e.to_string()))
    }
}
impl ServerCertVerifier for UriServerVerifier {
    fn verify_server_cert(&self,leaf:&CertificateDer<'_>,intermediates:&[CertificateDer<'_>],name:&ServerName<'_>,ocsp:&[u8],now:UnixTime)->Result<ServerCertVerified,rustls::Error>{
        self.inner()?.verify_server_cert(leaf,intermediates,name,ocsp,now)?;
        if self.role.is_some() && certificate_role(leaf).ok()!=self.role{return Err(rustls::Error::General("unexpected service URI SAN".into()));}
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self,message:&[u8],cert:&CertificateDer<'_>,sig:&rustls::DigitallySignedStruct)->Result<HandshakeSignatureValid,rustls::Error>{self.inner()?.verify_tls12_signature(message,cert,sig)}
    fn verify_tls13_signature(&self,message:&[u8],cert:&CertificateDer<'_>,sig:&rustls::DigitallySignedStruct)->Result<HandshakeSignatureValid,rustls::Error>{self.inner()?.verify_tls13_signature(message,cert,sig)}
    fn supported_verify_schemes(&self)->Vec<SignatureScheme>{provider().signature_verification_algorithms.supported_schemes()}
}

/// Tonic's convenience TLS config lacks a protocol-version setting. This bounded
/// incoming adapter uses an explicit TLS1.3 config and preserves verified peer
/// certificates in Tonic's TlsConnectInfo; no header can create that extension.
pub async fn incoming(address:std::net::SocketAddr,trust:Arc<Trust>)->Result<tokio_stream::wrappers::ReceiverStream<Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>,std::io::Error>>,Box<dyn std::error::Error>>{
    let listener=tokio::net::TcpListener::bind(address).await?;
    let acceptor=tokio_rustls::TlsAcceptor::from(trust.server_config()?);
    let (sender,receiver)=tokio::sync::mpsc::channel(32);
    let handshakes=Arc::new(tokio::sync::Semaphore::new(32));
    tokio::spawn(async move {
        loop {
            let Ok((stream,_))=listener.accept().await else {break};
            let Ok(permit)=handshakes.clone().try_acquire_owned() else {continue};
            let acceptor=acceptor.clone();let sender=sender.clone();
            tokio::spawn(async move {
                let _permit=permit;
                if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(3),acceptor.accept(stream)).await {
                    let _=tokio::time::timeout(Duration::from_secs(1),sender.send(Ok(stream))).await;
                }
            });
        }
    });
    Ok(tokio_stream::wrappers::ReceiverStream::new(receiver))
}

pub fn unix_now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).map(|v|v.as_secs()).unwrap_or(0)}

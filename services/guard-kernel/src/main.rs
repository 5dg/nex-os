use nex_guard_kernel::{Kernel, profile::Profile, protocol::guard_server::GuardServer, trust::Trust};
use std::{sync::Arc,time::Duration};
use tonic::transport::Server;

async fn shutdown(){let _=tokio::signal::ctrl_c().await;}
#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    // Both available profiles are synthetic. This is not a switch that can
    // accidentally turn test-PKI/ring/Ed25519 into a production CUI deployment.
    if std::env::var("APP_ENV").as_deref()!=Ok("development"){return Err("production transport/cryptographic deployment is unavailable".into());}
    let profile=Profile::from_env()?;
    if profile==Profile::Qualification && std::env::var("MODEL_PROVIDER").as_deref()!=Ok("development"){return Err("qualification forbids live model providers".into());}
    let trust=if profile==Profile::Qualification {Some(Arc::new(Trust::load()?))}else{None};
    let key=if profile==Profile::Development{std::fs::read(std::env::var("GUARD_KEY_FILE")?)?}else{vec![]};
    let mut kernel=Kernel::new_with_profile(std::env::var("OPA_URL")?,&key,profile,trust.clone())?;
    let database=if let Ok(file)=std::env::var("DATABASE_URL_FILE"){Some(std::fs::read_to_string(file)?)}else{std::env::var("DATABASE_URL").ok()};
    let mode=std::env::var("GUARD_MODE").unwrap_or_else(|_|"evaluation".into());
    if profile==Profile::Qualification && mode!="execution" {return Err("qualification requires the complete execution profile".into());}
    match mode.as_str(){
        "execution"=>{
            let database=database.filter(|v|!v.trim().is_empty()).ok_or("execution requires state store")?;
            let (model,export)=if profile==Profile::Development{(std::fs::read(std::env::var("MODEL_GUARD_KEY_FILE")?)?,std::fs::read(std::env::var("EXPORT_GUARD_KEY_FILE")?)?)}else{(vec![],vec![])};
            kernel=kernel.with_execution(database,&model,&export)?.with_evidence(std::env::var("EVIDENCE_URL")?,std::fs::read(std::env::var("EVIDENCE_KEY_FILE")?)?,std::fs::read(std::env::var("EVIDENCE_PUBLIC_FILE")?)?)?;
        }
        "evaluation" if database.is_none()=>{},
        _=>return Err("explicit execution profile required when state is configured".into()),
    }
    let address=std::env::var("GUARD_LISTEN_ADDR").unwrap_or_else(|_|"0.0.0.0:50051".into()).parse()?;
    let service=GuardServer::new(kernel).max_decoding_message_size(256*1024);
    let server=Server::builder().timeout(Duration::from_secs(15)).concurrency_limit_per_connection(16).add_service(service);
    eprintln!("Nex.Guard started; profile={}; synthetic data only",profile.name());
    if let Some(trust)=trust {
        server.serve_with_incoming_shutdown(nex_guard_kernel::trust::incoming(address,trust).await?,shutdown()).await?;
    }else{server.serve_with_shutdown(address,shutdown()).await?;}
    Ok(())
}

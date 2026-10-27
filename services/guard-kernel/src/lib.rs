use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};
mod evidence;
mod execution;
pub mod profile;
pub mod trust;
mod state;
use profile::Profile;
use trust::{Role,PeerIdentity,Trust};
use std::{sync::Arc,future::Future};
use tokio::sync::Semaphore;

pub mod protocol {
    tonic::include_proto!("nex.guard.v1");
}
use protocol::{Effect, EvaluateRequest, EvaluateResponse};

pub const POLICY: &str = include_str!("../../../policies/guard.rego");
pub fn policy_digest() -> String {
    format!("sha256:{:x}", Sha256::digest(POLICY.as_bytes()))
}

pub struct Kernel {
    client: reqwest::Client,
    opa_url: String,
    token: String,
    database: Option<String>,
    state: Option<state::StateStore>,
    profile: Profile,
    trust: Option<Arc<Trust>>,
    admission: Arc<Semaphore>,
    model_token: String,
    export_token: String,
    evidence: Option<evidence::Writer>,
}
impl Kernel {
    pub fn with_evidence(
        mut self,
        url: String,
        key: Vec<u8>,
        public: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client=if let Some(trust)=&self.trust {trust.http_client(Role::Evidence)?}else{self.client.clone()};
        self.evidence = Some(evidence::Writer::new(url, key, public,client,self.trust.clone())?);
        Ok(self)
    }

    pub fn new(opa_url: String, key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_profile(opa_url,key,Profile::Development,None)
    }
    pub fn new_with_profile(opa_url:String,key:&[u8],profile:Profile,trust:Option<Arc<Trust>>)->Result<Self,Box<dyn std::error::Error>> {
        if profile==Profile::Development && key.len() != 32 {
            return Err("32-byte control identity required".into());
        }
        let parsed = reqwest::Url::parse(&opa_url)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("valid policy endpoint required".into());
        }
        if profile==Profile::Qualification && (parsed.scheme()!="https" || trust.is_none()) {return Err("qualification requires verified policy HTTPS and workload identity".into());}
        let opa_url = opa_url.trim_end_matches('/').to_owned();
        let token = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Ok(Self {
            client: if let Some(tls)=&trust {tls.http_client(Role::Opa)?}else{reqwest::Client::builder().timeout(Duration::from_secs(3)).build()?},
            opa_url,
            token,
            database: None,
            state:None, profile,trust,admission:Arc::new(Semaphore::new(16)),
            model_token: String::new(),
            export_token: String::new(),
            evidence: None,
        })
    }
    pub fn with_execution(
        mut self,
        database: String,
        model: &[u8],
        export: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if self.profile==Profile::Development && (model.len() != 32 || export.len() != 32) {
            return Err("execution service identities required".into());
        }
        let model_token: String = model.iter().map(|b| format!("{b:02x}")).collect();
        let export_token: String = export.iter().map(|b| format!("{b:02x}")).collect();
        if self.profile==Profile::Development && (model_token == export_token || model_token == self.token || export_token == self.token) {
            return Err("distinct execution identities required".into());
        }
        let database = database.trim().to_owned();
        self.state=Some(state::StateStore::new(self.profile,&database)?);
        if database.is_empty() {
            return Err("state store configuration required".into());
        }
        self.database = Some(database);
        self.model_token = model_token;
        self.export_token = export_token;
        Ok(self)
    }
    fn authenticate<T>(&self,r:&Request<T>,roles:&[Role])->Result<PeerIdentity,Status>{
        if let Some(trust)=&self.trust {return trust.authenticate(r,roles);}
        let actual=r.metadata().get("authorization").and_then(|v|v.to_str().ok()).unwrap_or("");
        for role in roles {
            let token=match role{Role::Control=>&self.token,Role::Model=>&self.model_token,Role::Export=>&self.export_token,_=>continue};
            if !token.is_empty() && bool::from(actual.as_bytes().ct_eq(format!("Bearer {token}").as_bytes())) {return Ok(PeerIdentity::development(*role));}
        }
        Err(Status::unauthenticated("verified workload identity required"))
    }
    fn check_current(&self,peer:&PeerIdentity)->Result<(),Status>{if let Some(trust)=&self.trust {trust.check_current(peer)}else{Ok(())}}
    async fn bounded<T>(&self,operation:impl Future<Output=Result<Response<T>,Status>>)->Result<Response<T>,Status>{
        let _permit=self.admission.clone().try_acquire_owned().map_err(|_|Status::resource_exhausted("bounded request capacity exhausted"))?;
        tokio::time::timeout(Duration::from_secs(15),operation).await.map_err(|_|Status::deadline_exceeded("bounded authority request deadline exceeded"))?
    }
}

#[derive(Serialize)]
struct Actor {
    id: String,
    tenant_id: String,
    permissions: Vec<String>,
}
#[derive(Serialize)]
struct Resource {
    tenant_id: String,
    kind: String,
    classification: String,
    reader_ids: Vec<String>,
    approved_classifications: Vec<String>,
}
#[derive(Serialize)]
struct Input {
    actor: Actor,
    resource: Resource,
    action: String,
    delegation_valid: bool,
    delegation_permissions: Vec<String>,
    data_classification: String,
}
#[derive(Deserialize)]
struct Module {
    raw: String,
}
#[derive(Deserialize)]
struct Modules {
    result: Vec<Module>,
}
#[derive(Deserialize)]
struct Decision {
    effect: String,
    reason_code: String,
    policy_version: String,
}
#[derive(Deserialize)]
struct PolicyResult {
    result: Option<Decision>,
}

#[tonic::async_trait]
impl protocol::guard_server::Guard for Kernel {
    async fn check_readiness(&self,request:Request<protocol::ReadinessRequest>)->Result<Response<protocol::ReadinessResponse>,Status>{
        self.bounded(async {
            let peer=self.authenticate(&request,&[Role::Control,Role::Model,Role::Export])?;
            execution::ready(self).await?;
            self.check_current(&peer)?;
            Ok(Response::new(protocol::ReadinessResponse{ready:true,profile:self.profile.name().to_owned()}))
        }).await
    }
    async fn prepare_execution(
        &self,
        request: Request<protocol::PrepareRequest>,
    ) -> Result<Response<protocol::PreparedOperation>, Status> {
        self.bounded(execution::prepare(self, request)).await
    }
    async fn complete_execution(
        &self,
        request: Request<protocol::CompletionRequest>,
    ) -> Result<Response<protocol::ExecutionResponse>, Status> {
        self.bounded(execution::complete(self, request)).await
    }
    async fn execution_state(
        &self,
        request: Request<protocol::ExecutionRequest>,
    ) -> Result<Response<protocol::ExecutionResponse>, Status> {
        self.bounded(execution::state(self, request)).await
    }
    async fn authorize_execution(
        &self,
        request: Request<protocol::ExecutionRequest>,
    ) -> Result<Response<protocol::ExecutionResponse>, Status> {
        self.bounded(execution::execute(self, request)).await
    }
    async fn decide_approval(
        &self,
        request: Request<protocol::ApprovalRequest>,
    ) -> Result<Response<protocol::ExecutionResponse>, Status> {
        self.bounded(execution::approve(self, request)).await
    }
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let peer=self.authenticate(&request,&[Role::Control])?;
        let request = request.into_inner();
        if request.action.is_empty() && self.database.is_some() {
            execution::ready(self).await?;
        }
        let result=self.decide(request).await?;
        self.check_current(&peer)?;
        Ok(Response::new(result))
    }
}

impl Kernel {
    async fn decide(&self, request:EvaluateRequest)->Result<EvaluateResponse,Status>{
        if let Some(trust)=&self.trust {trust.check_own()?;}
        let actor = request.actor.unwrap_or_default();
        let resource = request.resource.unwrap_or_default();
        // Authoritative facts still originate in trusted DB resolution at this
        // stage. Never expose this service/key to users, models, or agent tasks.
        if request.action.len() > 100
            || actor.permissions.len() > 100
            || resource.reader_ids.len() > 1000
        {
            return Err(Status::invalid_argument("request limits exceeded"));
        }
        let input = Input {
            actor: Actor {
                id: actor.id,
                tenant_id: actor.tenant_id,
                permissions: actor.permissions,
            },
            resource: Resource {
                tenant_id: resource.tenant_id,
                kind: resource.kind,
                classification: resource.classification,
                reader_ids: resource.reader_ids,
                approved_classifications: resource.approved_classifications,
            },
            action: request.action,
            delegation_valid: request.delegation_valid,
            delegation_permissions: request.delegation_permissions,
            data_classification: request.data_classification,
        };
        let failure = || Status::unavailable("required policy dependency unavailable or invalid");
        let response = self
            .client
            .get(format!("{}/v1/policies", self.opa_url))
            .send()
            .await
            .map_err(|_| failure())?;
        if !response.status().is_success() {
            return Err(failure());
        }
        let modules: Modules = bounded_json(response,256*1024).await.map_err(|_| failure())?;
        if modules.result.len() != 1 || modules.result[0].raw != POLICY {
            return Err(failure());
        }
        let response = self
            .client
            .post(format!("{}/v1/data/nex/authz/decision", self.opa_url))
            .json(&serde_json::json!({"input": input}))
            .send()
            .await
            .map_err(|_| failure())?;
        if !response.status().is_success() {
            return Err(failure());
        }
        let result: PolicyResult = bounded_json(response,16384).await.map_err(|_| failure())?;
        let d = result.result.ok_or_else(failure)?;
        if d.policy_version != "alpha-guard-v1" || d.reason_code.is_empty() {
            return Err(failure());
        }
        let effect = match d.effect.as_str() {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            "require_approval" => Effect::RequireApproval,
            _ => return Err(failure()),
        };
        Ok(EvaluateResponse {
            effect: effect as i32,
            reason_code: d.reason_code,
            policy_version: d.policy_version,
            policy_digest: policy_digest(),
        })
    }
}

async fn bounded_json<T:serde::de::DeserializeOwned>(mut response:reqwest::Response,limit:usize)->Result<T,Status>{
    let fail=||Status::unavailable("bounded dependency response invalid");
    if response.content_length().is_some_and(|n|n>limit as u64){return Err(fail());}
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|fail())? {
        if bytes.len().saturating_add(chunk.len())>limit{return Err(fail());}bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_|fail())
}

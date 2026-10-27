use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tonic::Status;
use std::sync::Arc;
use crate::trust::Trust;
pub struct Writer {
    url: String,
    key: Vec<u8>,
    public: VerifyingKey,
    client:reqwest::Client,
    trust:Option<Arc<Trust>>,
}
#[derive(Deserialize)]
struct Proof {
    sequence: u64,
    head: String,
    signature: String,
    event_id: String,
    producer: String,
}
impl Writer {
    pub fn new(
        url: String,
        key: Vec<u8>,
        public: Vec<u8>,
        client:reqwest::Client,
        trust:Option<Arc<Trust>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let parsed = reqwest::Url::parse(&url)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("valid evidence endpoint required".into());
        }
        if trust.is_some() && parsed.scheme()!="https" {return Err("qualification requires verified evidence HTTPS".into());}
        if key.len() != 32 {
            return Err("evidence service identity required".into());
        };
        let public = VerifyingKey::from_bytes(public.as_slice().try_into()?)?;
        if public.is_weak() {
            return Err("non-weak pinned evidence public key required".into());
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_owned(),
            key,
            public,client,trust,
        })
    }
    pub async fn ready(&self) -> Result<(),Status> {
        if self.trust.is_some(){return self.challenge().await;}
        let response=self.client.get(format!("{}/healthz",self.url)).send().await.map_err(|_|Status::unavailable("required signer unavailable"))?;
        if !response.status().is_success(){return Err(Status::unavailable("required signer unavailable"));}Ok(())
    }
    fn capability(&self,audience:&str,body:&[u8])->Result<String,Status>{
        let fail=||Status::unavailable("required signed evidence dependency unavailable");
        let expires=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|fail())?.as_secs()+15;
        let claims=serde_json::to_vec(&serde_json::json!({"aud":audience,"digest":format!("{:x}",Sha256::digest(body)),"exp":expires})).map_err(|_|fail())?;
        let payload=URL_SAFE_NO_PAD.encode(claims);let mut mac=Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_|fail())?;mac.update(payload.as_bytes());
        Ok(format!("{payload}.{}",URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())))
    }
    async fn challenge(&self)->Result<(),Status>{
        let fail=||Status::unavailable("authenticated signer readiness failed");
        self.trust.as_ref().ok_or_else(fail)?.check_own()?;
        // Ring's system RNG uses the platform entropy source; no fabricated nonce.
        let random=rustls::crypto::ring::default_provider().secure_random;
        let mut bytes=[0u8;32];random.fill(&mut bytes).map_err(|_|fail())?;
        let nonce=bytes.iter().map(|v|format!("{v:02x}")).collect::<String>();
        let body=serde_json::to_vec(&serde_json::json!({"nonce":nonce})).map_err(|_|fail())?;
        let token=self.capability("evidence.challenge.kernel",&body)?;
        let response=self.client.post(format!("{}/challenge/kernel",self.url)).header("content-type","application/json").header("authorization",format!("Capability {token}")).body(body).send().await.map_err(|_|fail())?;
        if !response.status().is_success(){return Err(fail());}
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Challenge {producer:String,nonce:String,key_fingerprint:String,signature:String}
        let proof:Challenge=crate::bounded_json(response,4096).await.map_err(|_|fail())?;
        let fingerprint=format!("sha256:{:x}",Sha256::digest(self.public.as_bytes()));
        if proof.producer!="kernel"||proof.nonce!=nonce||proof.key_fingerprint!=fingerprint{return Err(fail());}
        let mut message=b"nex.evidence.readiness.v1\0".to_vec();
        for field in ["kernel",nonce.as_str(),fingerprint.as_str(),"spiffe://nex.local/service/evidence"]{message.extend((field.len()as u64).to_be_bytes());message.extend(field.as_bytes());}
        let signature=URL_SAFE_NO_PAD.decode(proof.signature).map_err(|_|fail())?;
        self.public.verify(&message,&Signature::from_slice(&signature).map_err(|_|fail())?).map_err(|_|fail())?;
        self.trust.as_ref().ok_or_else(fail)?.check_own()?;
        Ok(())
    }
    pub async fn append(
        &self,
        event: serde_json::Value,
    ) -> Result<serde_json::Value, Status> {
        let fail = || Status::unavailable("required signed evidence dependency unavailable");
        let id = event
            .get("event_id")
            .and_then(|x| x.as_str())
            .ok_or_else(fail)?;
        let body = serde_json::to_vec(&event).map_err(|_| fail())?;
        if let Some(trust)=&self.trust {trust.check_own()?;}
        let token=self.capability("evidence.append.kernel",&body)?;
        let response = self.client
            .post(format!("{}/append/kernel", self.url))
            .header("content-type", "application/json")
            .header("authorization", format!("Capability {token}"))
            .body(body)
            .send()
            .await
            .map_err(|_| fail())?;
        if !response.status().is_success() {
            return Err(fail());
        };
        let raw: serde_json::Value = crate::bounded_json(response,16384).await.map_err(|_| fail())?;
        let proof: Proof = serde_json::from_value(raw.clone()).map_err(|_| fail())?;
        let signature = URL_SAFE_NO_PAD
            .decode(proof.signature)
            .map_err(|_| fail())?;
        let signature = Signature::from_slice(&signature).map_err(|_| fail())?;
        let message = format!(
            "nex-evidence-v1:{}:{}:{}:{}",
            proof.sequence, proof.head, proof.event_id, proof.producer
        );
        if proof.event_id != id
            || proof.producer != "kernel"
            || self.public.verify(message.as_bytes(), &signature).is_err()
        {
            return Err(fail());
        };
        Ok(raw)
    }
}

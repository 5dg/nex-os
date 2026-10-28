#!/usr/bin/env python3
"""E-owned pinned compilation and thin packaging from one verified snapshot."""
import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import shutil
import subprocess
import threading
import sys

sys.dont_write_bytecode = True
from candidate import load
from image_record import payload
from source_record import atomic_json, identity, sha256
from resource_admission import load_policy, second_admission, summarize_measurements

COMPILERS = {
 "go": "golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5",
 "rust": "rust:1.99.1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be",
 "node": "node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df",
}
GIB = 1024 ** 3
FRONTEND = "docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e"


class Builder:
 def __init__(self, args):
  self.candidate, self.base, self.source = load(args.candidate)
  self.args = args
  self.path = self.base / "builds" / args.build
  if self.path.exists():
   raise ValueError("build output already exists; retain it and use a new candidate")
  self.path.mkdir(mode=0o700, parents=True)
  self.bin, self.package, self.work = (self.path / name for name in ("bin", "package", "work"))
  for path in (self.bin, self.package, self.work): path.mkdir()
  self.prefix = ["docker", "--host=unix:///var/run/docker.sock"]
  self.env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
  raw = subprocess.check_output(self.docker("info", "--format",
   '{"driver":{{json .Driver}},"data_root":{{json .DockerRootDir}},"version":{{json .ServerVersion}}}'), env=self.env, text=True)
  self.info = json.loads(raw)
  self.docker_fs = Path(self.info["data_root"])
  while not self.docker_fs.exists(): self.docker_fs = self.docker_fs.parent
  self.reserve = 2 * GIB
  self.manifest = self.path / "manifest.json"
  self.record = {"schema_version": 1, "build_mode": "canonical-container", "production_attestation": False,
   "source": self.candidate["source"], "run_id": self.candidate["run_id"], "build_id": args.build,
   "status": "building", "commands": [], "images": {}, "builders": {},
   "resource_budget": {"docker": self.info, "docker_minimum_free": 8*GIB, "temporary_minimum_free": 6*GIB,
    "reserve": self.reserve, "cargo_jobs": 2, "concurrent_builds": 1},
   "coordinator_python": sys.version, "dockerfile_frontend": FRONTEND,
   "started_at": self.now()}
  policy = load_policy(args.second_admission_policy, self.source, self.candidate["source"]["inputs"]["sha256"], self.info["driver"])
  self.record["resource_budget"]["second_admission_policy"] = policy
  second = None
  if args.build == "two":
   first_path = self.base / "builds/one/manifest.json"
   if first_path.is_symlink() or not first_path.is_file(): raise ValueError("regular completed first-build manifest required")
   first_bytes = first_path.read_bytes()
   second = second_admission(self.candidate, json.loads(first_bytes), hashlib.sha256(first_bytes).hexdigest(), policy, self.info)
   self.record["resource_budget"]["second_admission"] = second
   self.record["resource_budget"].update({filesystem+"_minimum_free": minimum for filesystem, minimum in second["minimum_free"].items()})
  self.eviction_plan = {}
  if args.resource_plan:
   plan = json.loads(args.resource_plan.read_text())
   if plan.get("schema_version") != 1 or plan.get("strategy") != "pinned-containers-bind-outputs" or plan.get("source_input_sha256") != self.candidate["source"]["inputs"]["sha256"] or plan.get("docker_driver") != self.info["driver"] or plan.get("lead_review") != "approved":
    raise ValueError("an explicitly reviewed source/driver-bound resource plan is required")
   for filesystem in ("docker", "temporary"):
    minimum, peak = plan.get(filesystem+"_minimum_free"), plan.get(filesystem+"_estimated_peak_additional")
    if type(minimum) is not int or type(peak) is not int or peak <= 0 or minimum < peak+self.reserve:
     raise ValueError("resource estimate must preserve the unchanged 2 GiB reserve")
    if second and (peak < second["estimated_peak_additional"][filesystem] or minimum < second["minimum_free"][filesystem]):
     raise ValueError("explicit second plan cannot lower measured-policy admission floors")
   self.record["resource_budget"].update({key:plan[key] for key in ("docker_minimum_free","temporary_minimum_free")})
   self.record["resource_budget"]["reviewed_plan"] = {"sha256":sha256(args.resource_plan),"record":plan}
   for eviction in plan.get("compiler_cache_evictions", []):
    role = eviction.get("after")
    expected = COMPILERS.get("go" if role == "gosu" else role)
    if role not in ("gosu", "rust") or role in self.eviction_plan or eviction.get("requested") != expected or not re.fullmatch(r"sha256:[0-9a-f]{64}", eviction.get("image_id", "")):
     raise ValueError("resource plan can whitelist only exact Go/gosu or Rust compiler image IDs")
    self.eviction_plan[role] = eviction
  self.initial_free = self.measure_free()
  self.record["resource_budget"]["measurements"] = {"schema_version":1,"complete":False,"initial_free":self.initial_free}
  atomic_json(self.manifest, self.record)
  if self.initial_free["docker_free"] < self.record["resource_budget"]["docker_minimum_free"] or self.initial_free["temporary_free"] < self.record["resource_budget"]["temporary_minimum_free"]:
   self.record.update(status="blocked",reason="resource admission failed")
   atomic_json(self.manifest,self.record)
   raise ValueError("canonical resource admission failed; E must review capacity")

 @staticmethod
 def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

 def docker(self, *args): return self.prefix + list(args)

 def measure_free(self):
  return {"docker_free":shutil.disk_usage(self.docker_fs).free,"temporary_free":shutil.disk_usage(self.path).free}

 def run(self, name, command, capture=False):
  floors = self.measure_free()
  if min(floors.values()) < self.reserve: raise ValueError("resource reserve exhausted; further admission stopped")
  log = self.path / (name + ".log")
  item = {"name": name, "command": command, "started_at": self.now(),"observed_initial_free":dict(floors)}
  self.record["commands"].append(item)
  atomic_json(self.manifest, self.record)
  stop = threading.Event()
  sampling_errors = []
  def observe():
   try:
    while not stop.wait(1):
     for key,value in self.measure_free().items(): floors[key] = min(floors[key],value)
   except OSError:
    sampling_errors.append("filesystem sampling failed")
  observer = threading.Thread(target=observe, daemon=True)
  observer.start()
  try:
   with log.open("wb") as stream: result = subprocess.run(command, env=self.env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
   item["exit_code"] = result.returncode
  except subprocess.TimeoutExpired as error:
   item.update(exit_code=None, timed_out=True)
   if name.endswith("-package"):
    self.record["packaging_reconciliation_required"] = True
   raise ValueError(f"{name} timed out; retain partial output and reconcile owned runtime/build state") from error
  except BaseException:
   item.update(exit_code=None, interrupted=True)
   raise
  finally:
   stop.set()
   observer.join()
   final_free = self.measure_free()
   for key,value in final_free.items(): floors[key] = min(floors[key],value)
   item.update(ended_at=self.now(), observed_minimum_free=floors,observed_final_free=final_free,
    log={"path": log.name, "sha256": sha256(log)} if log.exists() else None)
   if sampling_errors: item["resource_sampling_failed"] = True
   atomic_json(self.manifest, self.record)
  if sampling_errors: raise ValueError("resource sampling failed; no complete first-build measurement")
  if result.returncode:
   if name.endswith("-package"):
    self.record["packaging_reconciliation_required"] = True
    atomic_json(self.manifest,self.record)
   raise ValueError(f"{name} failed; inspect retained {log.name}")
  if min(floors.values()) < self.reserve: raise ValueError(f"{name} breached resource reserve; further admission stopped")
  return log.read_text() if capture else None

 def compiler(self, role):
  image = COMPILERS["go" if role == "gosu" else role]
  self.run(role+"-pull", self.docker("pull", image))
  details = json.loads(self.run(role+"-identity", self.docker("image", "inspect", image, "--format",
   '{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'), True))
  if details["os"] != "linux" or details["architecture"] != "amd64": raise ValueError("Linux amd64 compiler required")
  self.record["builders"][role] = {"requested": image, **details}
  nonce = secrets.token_hex(6)
  container_name = f"nex-alpha04-{self.candidate['run_id']}-build-{self.args.build}-{role}-{nonce}"
  owner = {"org.nex.compiler.run":self.candidate["run_id"],"org.nex.compiler.build":self.args.build,
   "org.nex.compiler.role":role,"org.nex.compiler.nonce":nonce,"org.nex.source.inputs":self.candidate["source"]["inputs"]["sha256"]}
  command = self.docker("run", "--rm", "--name",container_name,"--cidfile",str(self.path/(role+".cid")),"--init", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
   "--user", f"{os.getuid()}:{os.getgid()}", "--cpus=2", "--memory="+{"go":"4g","gosu":"4g","rust":"8g","node":"6g"}[role],
   "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m")
  for key,value in owner.items(): command += ["--label",key+"="+value]
  for src, dst, readonly in ((self.source,"/src",True),(self.work,"/work",False),(self.bin,"/out",False),
   (self.package,"/package",False),(self.args.ca.resolve(),"/run/ca.crt",True)):
   command += ["--mount", f"type=bind,src={src},dst={dst}"+(",readonly" if readonly else "")]
  command += ["-w","/src"]
  for key, value in {"GOTOOLCHAIN":"local","CGO_ENABLED":"0","RUSTUP_TOOLCHAIN":"1.99.1",
   "SSL_CERT_FILE":"/run/ca.crt","CARGO_HTTP_CAINFO":"/run/ca.crt","NODE_EXTRA_CA_CERTS":"/run/ca.crt",
   "NEXT_TELEMETRY_DISABLED":"1","NODE_OPTIONS":"--max-old-space-size=4096",
   "SOURCE_DATE_EPOCH":str(self.candidate["source"]["source_epoch"]),
   "NEX_SOURCE_INPUT_SHA256":self.candidate["source"]["inputs"]["sha256"]}.items(): command += ["-e",key+"="+value]
  for key in ("HTTP_PROXY","HTTPS_PROXY","NO_PROXY","http_proxy","https_proxy","no_proxy"):
   if key in self.env: command += ["-e",key]
  command += [image,"sh","/src/scripts/canonical-compiler.sh",role]
  try:
   self.run(role+"-compile", command)
  finally:
   self.stop_owned_compiler(role,container_name,owner,details["id"])

 def stop_owned_compiler(self, role, name, owner, image_id):
  command = self.docker("container","inspect",name,"--format",'{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}}}')
  observed = subprocess.run(command,env=self.env,capture_output=True,text=True,timeout=20)
  check = {"name":name,"command":command,"exit_code":observed.returncode,"at":self.now()}
  self.record.setdefault("compiler_cleanup",[]).append(check)
  if observed.returncode:
   if "No such container" in observed.stderr or "No such object" in observed.stderr:
    check["status"] = "already-removed"
    atomic_json(self.manifest,self.record)
    return
   raise ValueError("owned compiler state unknown; stop further admission and reconcile")
  actual = json.loads(observed.stdout)
  if actual["name"] != "/"+name or actual["image"] != image_id or any((actual.get("labels") or {}).get(key) != value for key,value in owner.items()):
   raise ValueError("compiler cleanup ownership mismatch; preserve container for E review")
  cid_path = self.path/(role+".cid")
  if cid_path.exists() and (cid_path.is_symlink() or cid_path.read_text().strip() != actual["id"]):
   raise ValueError("compiler CID differs from inspected owned container; preserve for E review")
  check["container_id"] = actual["id"]
  def cleanup_command(command):
   # Safety cleanup cannot depend on writable logs/manifest/free disk. Persist
   # its bounded metadata only AFTER the daemon-owned writer is stopped.
   completed = subprocess.run(command,env=self.env,capture_output=True,text=True,timeout=60)
   check.setdefault("cleanup_commands",[]).append({"command":command,"exit_code":completed.returncode})
   if completed.returncode:
    raise ValueError("owned compiler cleanup failed; no further admission")
  if actual["running"]:
   cleanup_command(self.docker("stop","--time","20",actual["id"]))
  remaining = subprocess.run(self.docker("container","inspect",actual["id"],"--format","{{.State.Running}}"),env=self.env,capture_output=True,text=True,timeout=20)
  if remaining.returncode == 0:
   if remaining.stdout.strip() != "false": raise ValueError("owned compiler still running; no further admission")
   cleanup_command(self.docker("rm",actual["id"]))
  elif "No such container" not in remaining.stderr and "No such object" not in remaining.stderr:
   raise ValueError("owned compiler final state unknown; no further admission")
  check["status"] = "stopped-and-removed"
  atomic_json(self.manifest,self.record)

 def save_image(self, name, image, extra):
  details = json.loads(self.run(name+"-image", self.docker("image","inspect",image,"--format",
   '{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"layers":{{json .RootFS.Layers}}}'), True))
  archives = self.path/"images"
  archives.mkdir(exist_ok=True)
  archive = archives/(name+".tar")
  self.run(name+"-save",self.docker("image","save","-o",str(archive),details["id"]))
  details.update(extra)
  details.update(archive={"path":"images/"+archive.name,"sha256":sha256(archive)},
   payload=payload(archive,self.path/(name+"-payload.json")))
  self.record["images"][name] = details
  atomic_json(self.manifest,self.record)

 def compiler_boundary(self, role):
  names = ("control","dev-issuer","model","executor","worker","evidence","qualification-edge","qualification-policy-edge","qualification-pki","qualification-issuer","qualification-receiver-readiness") if role == "gosu" else ("guard-kernel",)
  exported = {}
  paths = [self.bin/name for name in names]
  if role == "gosu": paths += [self.package/"trust/ca-certificates.crt",self.package/"postgres/usr/local/bin/gosu",self.package/"postgres/usr/local/share/nex/gosu-build.txt",self.package/"postgres/usr/local/share/nex/gosu-dependency-overlay.json"]
  for path in paths:
   if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
    raise ValueError("missing or unsupported fresh compiler export: "+path.name)
   if path.parent == self.bin and not os.access(path,os.X_OK):
    raise ValueError("fresh compiler binary is not executable: "+path.name)
   exported[str(path.relative_to(self.path))] = {"sha256":sha256(path),"mode":path.stat().st_mode & 0o7777}
  metadata_names = ("go-version.txt","go-target.txt","go-compiler.sha256","runtime-trust-bundle.sha256") if role == "gosu" else ("rustc-version.txt","rust-target.txt","rustc-compiler.sha256","rust-libc.txt","guard-linked-libraries.txt")
  for name in metadata_names:
   path = self.bin/name
   if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
    raise ValueError("missing compiler/ABI metadata before phase scratch cleanup")
   exported[str(path.relative_to(self.path))] = {"sha256":sha256(path),"text":path.read_text()}
  self.record.setdefault("phase_exports",{})[role] = exported
  atomic_json(self.manifest,self.record)
  eviction = self.eviction_plan.get(role)
  if eviction:
   actual = self.record["builders"][role]
   if actual["id"] != eviction["image_id"] or actual["requested"] != eviction["requested"]:
    raise ValueError("compiler eviction differs from the exact reviewed resource plan")
   references = self.run(role+"-eviction-references",self.docker("ps","-aq","--filter","ancestor="+actual["id"]),True)
   if references.strip():
    raise ValueError("reviewed compiler cache still has a container reference; preserve it")
   # Normal exact-ID removal only: no force, prune, unrelated image or volume.
   self.run(role+"-evict-reviewed-compiler",self.docker("image","rm",actual["id"]))
  # Only scratch created by THIS build. Exported outputs and raw logs persist.
  owned = {"gosu":("go-cache","gopath","gosu","gosu-go-cache","gosu-gopath","tmp"),"rust":("target","cargo")}[role]
  discarded = []
  for name in owned:
   path = self.work/name
   if path.exists():
    shutil.rmtree(path)
    discarded.append(name)
  self.record.setdefault("phase_boundaries",[]).append({"after":role,"discarded_own_scratch":discarded,"compiler_eviction_reviewed":bool(eviction),"at":self.now()})
  atomic_json(self.manifest,self.record)

 def image(self, name, dockerfile):
  tag = f"nex-alpha04-{self.candidate['run_id']}-{name}:{self.args.build}"
  self.run(name+"-package",self.docker("build","--no-cache","--secret",f"id=proxy_ca,src={self.args.ca.resolve()}",
   "--build-arg","BUILDKIT_SYNTAX="+FRONTEND,
   "--label","org.nex.qualification.builder=canonical-container",
   "--label","org.opencontainers.image.revision="+self.candidate["source"]["revision"],
   "--label","org.nex.source.inputs="+self.candidate["source"]["inputs"]["sha256"],
   "--build-arg","SOURCE_DATE_EPOCH="+str(self.candidate["source"]["source_epoch"]),
   "-f",str(self.source/dockerfile),"-t",tag,str(self.package)))
  self.save_image(name,tag,{"tag":tag,"dockerfile":dockerfile,"dockerfile_sha256":sha256(self.source/dockerfile)})

 def build(self):
  try:
   self.compiler("go")
   self.compiler("gosu")
   self.compiler_boundary("gosu")
   self.compiler("rust")
   self.compiler_boundary("rust")
   shutil.copytree(self.source/"apps/workspace",self.work/"workspace",ignore=shutil.ignore_patterns("node_modules",".next","__pycache__"))
   self.compiler("node")
   shutil.copytree(self.bin,self.package/"bin")
   binaries = {p.name:sha256(p) for p in sorted(self.bin.iterdir()) if p.is_file() and os.access(p,os.X_OK)}
   self.record["binaries"] = binaries
   self.record["compiler_metadata"] = {p.name: {"sha256": sha256(p), "text": p.read_text()}
    for p in sorted(self.bin.iterdir()) if p.is_file() and not os.access(p,os.X_OK)}
   atomic_json(self.bin/"build-inputs.json",{"schema_version":2,"build_mode":"canonical-container","production_attestation":False,
    "source_revision":self.candidate["source"]["revision"],"inputs":self.candidate["source"]["inputs"],"binaries":binaries})
   for name, dockerfile in (("control","deploy/qualification/Dockerfile.control.runtime"),("guard","deploy/local/Dockerfile.guard"),
    ("fixtures","deploy/qualification/Dockerfile.fixtures.runtime"),("workspace","deploy/qualification/Dockerfile.workspace.runtime"),
    ("postgres","deploy/qualification/Dockerfile.postgres.runtime")): self.image(name,dockerfile)
   opa = json.loads((self.source/"deploy/qualification/compose.yaml").read_text())["services"]["opa"]["image"]
   variable = re.fullmatch(r"\$\{NEX_OPA_IMAGE:-(.+)\}", opa)
   if variable: opa = variable.group(1)
   self.run("opa-pull",self.docker("pull",opa))
   self.save_image("opa",opa,{"requested":opa})
   if identity(self.source,canonical=True) != self.candidate["source"]: raise ValueError("source changed during build")
   self.record.update(status="built",ended_at=self.now())
   shutil.rmtree(self.work)  # Only this newly created compilation scratch, not state.
   self.record["compilation_scratch_discarded"] = True
   self.record["resource_budget"]["measurements"] = summarize_measurements(self.initial_free,self.record["commands"],self.measure_free())
   atomic_json(self.manifest,self.record)
   self.candidate["builds"][self.args.build] = {"path":str(self.manifest.relative_to(self.base)),"sha256":sha256(self.manifest)}
   atomic_json(self.args.candidate,self.candidate)
  except BaseException as error:
   self.record.update(status="failed",error=str(error),ended_at=self.now())
   raise
  finally: atomic_json(self.manifest,self.record)


if __name__ == "__main__":
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--candidate",type=Path,required=True)
 parser.add_argument("--build",choices=("one","two"),required=True)
 parser.add_argument("--ca",type=Path,default=Path(os.environ.get("NEX_BUILD_CA","/etc/ssl/certs/ca-certificates.crt")))
 parser.add_argument("--resource-plan",type=Path)
 parser.add_argument("--second-admission-policy",type=Path,default=Path(os.environ["NEX_CANONICAL_SECOND_ADMISSION_POLICY"]) if os.environ.get("NEX_CANONICAL_SECOND_ADMISSION_POLICY") else None)
 args = parser.parse_args()
 try:
  if not args.ca.is_file(): raise ValueError("verified build CA bundle required")
  Builder(args).build()
 except (ValueError,OSError,subprocess.CalledProcessError) as error: parser.exit(1,str(error)+"\n")

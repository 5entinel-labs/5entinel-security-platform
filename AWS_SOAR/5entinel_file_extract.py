import os
import re
import base64
import hashlib
import boto3

from eks_token import get_token
from kubernetes import client
from kubernetes.stream import stream

AWS_REGION = "your_region"

s3 = boto3.client("s3", region_name=AWS_REGION)
eks = boto3.client("eks", region_name=AWS_REGION)

# Process these event types
TARGET_EVENT_TYPES = {
    "DVWA_UPLOAD_MOVE",
    "ARTIFACT_WRITE",
    "ARTIFACT_WRITE_SUSP_EXT",
    "ARTIFACT_WRITE_ARCHIVE",
    "ARTIFACT_FETCH_TO_UPLOAD"
}

EVENT_TYPE_RE = re.compile(
    r"\b(DVWA_UPLOAD_MOVE|ARTIFACT_WRITE_SUSP_EXT|ARTIFACT_WRITE_ARCHIVE|ARTIFACT_WRITE|ARTIFACT_FETCH_TO_UPLOAD)\b"
)


def _pick(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _extract_kv(log_line: str, key: str):
    """
    Extract key=value from Falco output line.
    Values can include spaces so we stop at the next " <word>=" token.
    """
    if not log_line:
        return None
    pattern = rf"(?:^|\s){re.escape(key)}=(.*?)(?=\s+\w+=|$)"
    m = re.search(pattern, log_line)
    return m.group(1) if m else None


def _get_best_log_and_time(event: dict):
    # log
    log_line = event.get("log")
    if not log_line:
        log_line = _pick(event, ["falco", "log"])
    if not log_line:
        log_line = _pick(event, ["falco", "raw_message", "log"])

    # time
    time_val = event.get("time")
    if not time_val:
        time_val = _pick(event, ["falco", "time"])
    if not time_val:
        time_val = _pick(event, ["falco", "raw_message", "time"])

    return log_line, time_val


def normalize_input(event: dict) -> dict:
    """
    Normalize Step Functions input into a stable schema:
      {
        event_type,
        k8s: {namespace,pod,container},
        file: {path, src},
        meta: {time, raw_log}
      }

    Accepts raw records where the real log might be:
      - event["log"]
      - event["falco"]["log"]
      - event["falco"]["raw_message"]["log"]
    """
    log_line, time_val = _get_best_log_and_time(event)

    out = {
        "event_type": event.get("event_type"),
        "k8s": {"namespace": None, "pod": None, "container": None},
        "file": {"path": None, "src": None},
        "meta": {"time": time_val, "raw_log": log_line},
    }

    # If caller already normalized
    if isinstance(event.get("k8s"), dict):
        out["k8s"]["namespace"] = event["k8s"].get("namespace") or event["k8s"].get("ns")
        out["k8s"]["pod"] = event["k8s"].get("pod")
        out["k8s"]["container"] = event["k8s"].get("container")

    if isinstance(event.get("file"), dict):
        out["file"]["path"] = event["file"].get("path")
        out["file"]["src"] = event["file"].get("src")

    # Prefer falco.rule when present (some pipelines populate it)
    if not out["event_type"]:
        out["event_type"] = _pick(event, ["falco", "rule"]) or _pick(event, ["falco", "raw_message", "rule"])

    # Parse from log line
    if log_line:
        if not out["event_type"]:
            m = EVENT_TYPE_RE.search(log_line)
            if m:
                out["event_type"] = m.group(1)

        # K8S target info inside Falco output line
        out["k8s"]["pod"] = out["k8s"]["pod"] or _extract_kv(log_line, "pod") or _extract_kv(log_line, "k8s_pod_name")
        out["k8s"]["namespace"] = out["k8s"]["namespace"] or _extract_kv(log_line, "ns") or _extract_kv(log_line, "k8s_ns_name")
        out["k8s"]["container"] = out["k8s"]["container"] or _extract_kv(log_line, "container") or _extract_kv(log_line, "container_name")

        # File path mapping based on event type
        if not out["file"]["path"]:
            et = out["event_type"]
            if et == "DVWA_UPLOAD_MOVE":
                out["file"]["path"] = _extract_kv(log_line, "dst")
                out["file"]["src"] = _extract_kv(log_line, "src")
            elif et in {"ARTIFACT_WRITE", "ARTIFACT_WRITE_SUSP_EXT", "ARTIFACT_WRITE_ARCHIVE", "ARTIFACT_FETCH_TO_UPLOAD"}:
                out["file"]["path"] = _extract_kv(log_line, "artifact_path")

    return out


def get_cluster_endpoint_and_ca(cluster_name: str):
    resp = eks.describe_cluster(name=cluster_name)["cluster"]
    return resp["endpoint"], resp["certificateAuthority"]["data"]


def build_k8s_api_client(cluster_name: str) -> client.ApiClient:
    endpoint, ca_b64 = get_cluster_endpoint_and_ca(cluster_name)

    ca_path = "/tmp/eks-ca.crt"
    with open(ca_path, "wb") as f:
        f.write(base64.b64decode(ca_b64))

    token = get_token(cluster_name=cluster_name, region_name=AWS_REGION)["status"]["token"]

    cfg = client.Configuration()
    cfg.host = endpoint
    cfg.ssl_ca_cert = ca_path
    cfg.verify_ssl = True
    cfg.api_key = {"authorization": f"Bearer {token}"}

    return client.ApiClient(cfg)


def exec_read_file_base64(v1: client.CoreV1Api, namespace: str, pod: str, container: str, file_path: str) -> str:
    cmd = ["sh", "-c", f"base64 < '{file_path}' 2>&1 | tr -d '\\n'"]
    return stream(
        v1.connect_get_namespaced_pod_exec,
        pod,
        namespace,
        container=container,
        command=cmd,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
        _preload_content=True,
    )


def build_s3_key(file_path: str) -> str:
    basename = file_path.split("/")[-1] if file_path else "unknown"
    # S3 key는 대부분의 UTF-8 문자를 지원하지만, 호환성 위해 안전문자만 남김 [web:267]
    safe_basename = re.sub(r"[^A-Za-z0-9._-]", "_", basename)
    return safe_basename



def lambda_handler(event, context):
    """
    Required env vars:
      - EKS_CLUSTER_NAME
      - S3_BUCKET
    Optional:
      - S3_PREFIX (default: "file")
    """
    cluster_name = os.environ["EKS_CLUSTER_NAME"]
    bucket = os.environ["S3_BUCKET"]
    

    norm = normalize_input(event)
    et = norm["event_type"]

    if et not in TARGET_EVENT_TYPES:
        return {"uploaded": False, "reason": "not_target_event_type", "normalized": norm}

    namespace = norm["k8s"]["namespace"]
    pod = norm["k8s"]["pod"]
    container = norm["k8s"]["container"]
    file_path = norm["file"]["path"]

    missing = [k for k, v in {
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "file_path": file_path
    }.items() if not v]

    if missing:
        return {
            "uploaded": False,
            "reason": "missing_required_fields",
            "missing": missing,
            "normalized": norm,
        }

    # Init k8s client
    try:
        api_client = build_k8s_api_client(cluster_name)
        v1 = client.CoreV1Api(api_client)
    except Exception as e:
        return {"uploaded": False, "reason": "k8s_client_init_failed", "error": str(e), "normalized": norm}

    # Read file via exec
    try:
        out = exec_read_file_base64(v1, namespace, pod, container, file_path)
    except Exception as e:
        return {"uploaded": False, "reason": "k8s_exec_failed", "error": str(e), "normalized": norm}

    lowered = (out or "").lower()

    if "no such file" in lowered or "not found" in lowered:
        return {
            "uploaded": False,
            "reason": "file_not_found_skip",
            "normalized": norm,
            "k8s_exec_output": (out or "")[:500],
        }

    if "permission denied" in lowered:
        return {
            "uploaded": False,
            "reason": "permission_denied",
            "normalized": norm,
            "k8s_exec_output": (out or "")[:500],
        }

    # Base64 decode
    try:
        file_bytes = base64.b64decode((out or "").encode("utf-8"))
    except Exception:
        return {
            "uploaded": False,
            "reason": "invalid_base64_skip",
            "normalized": norm,
            "k8s_exec_output": (out or "")[:500],
        }

    # Upload to S3
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    key = build_s3_key(file_path)

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=file_bytes,
        ContentType="application/octet-stream",
        Metadata={
            "event_type": str(et),
            "namespace": str(namespace),
            "pod": str(pod),
            "container": str(container),
            "file_path": str(file_path),
            "sha256": str(sha256),
        }
    )

    return {
        "uploaded": True,
        "bucket": bucket,
        "key": key,
        "bytes": len(file_bytes),
        "sha256": sha256,
        "normalized": norm,
    }

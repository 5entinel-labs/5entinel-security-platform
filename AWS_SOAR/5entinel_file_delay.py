import os
import re
import json
import base64
import boto3
import hashlib
import urllib.request
import urllib.error
from datetime import datetime

from eks_token import get_token
from kubernetes import client
from kubernetes.stream import stream

AWS_REGION = "your_region"
CLUSTER_NAME = "your_eks_cluster_name"

eks = boto3.client("eks", region_name=AWS_REGION)

DEFAULT_QUAR_DIR = "/var/www/html/hackable/quarantine"


def _extract_kv(log_line: str, key: str):
    pattern = rf"(?:^|\s){re.escape(key)}=(.*?)(?=\s+\w+=|$)"
    m = re.search(pattern, log_line)
    return m.group(1) if m else None


def _pick_first(d: dict, paths: list[list[str]]):
    """
    여러 후보 경로 중 첫 번째로 존재하는 값을 반환.
    paths 예: [["falco","log"], ["falco","raw_message","log"]]
    """
    for path in paths:
        cur = d
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return None


def _extract_falco_fields(event: dict):
    """
    서로 다른 입력 스키마를 모두 고려해서 falco time/log_line을 뽑는다.
    - 케이스 A: {"falco": {"log": "...", "time":"..." }}
    - 케이스 B: {"falco": {"raw_message": {"log":"...", "time":"..."}}}
    """
    log_line = _pick_first(event, [
        ["falco", "log"],
        ["falco", "raw_message", "log"],
        ["falco", "raw_message", "message"],
        ["raw_message", "log"],
        ["raw_message", "message"],
    ])

    t = _pick_first(event, [
        ["falco", "time"],
        ["falco", "raw_message", "time"],
        ["time"],
    ])

    if log_line is not None and not isinstance(log_line, str):
        log_line = str(log_line)

    return t, log_line


def normalize_input(event: dict) -> dict:
    """
    우선순위:
      1) event.file_extract.Payload.normalized (file extract 결과 기반)
      2) 여러 구조의 falco 로그 라인에서 파싱(dst/pod/ns/container 등)
    """
    out = {
        "event_type": None,
        "k8s": {"namespace": None, "pod": None, "container": None},
        "file": {"path": None},
        "meta": {"time": None, "raw_log": None},
        "extract": {"sha256": None},
    }

    fe = (event.get("file_extract") or {}).get("Payload") or {}
    norm = fe.get("normalized") or {}
    if norm:
        out["event_type"] = norm.get("event_type")
        out["k8s"]["namespace"] = (norm.get("k8s") or {}).get("namespace")
        out["k8s"]["pod"] = (norm.get("k8s") or {}).get("pod")
        out["k8s"]["container"] = (norm.get("k8s") or {}).get("container")
        out["file"]["path"] = (norm.get("file") or {}).get("path")
        out["meta"]["time"] = (norm.get("meta") or {}).get("time")
        out["meta"]["raw_log"] = (norm.get("meta") or {}).get("raw_log")
        out["extract"]["sha256"] = fe.get("sha256")

    t, log_line = _extract_falco_fields(event)
    out["meta"]["time"] = out["meta"]["time"] or t
    out["meta"]["raw_log"] = out["meta"]["raw_log"] or log_line

    if log_line:
        out["k8s"]["pod"] = out["k8s"]["pod"] or _extract_kv(log_line, "pod") or _extract_kv(log_line, "k8s_pod_name")
        out["k8s"]["namespace"] = out["k8s"]["namespace"] or _extract_kv(log_line, "ns") or _extract_kv(log_line, "k8s_ns_name")
        out["k8s"]["container"] = out["k8s"]["container"] or _extract_kv(log_line, "container") or _extract_kv(log_line, "container_name")

        out["file"]["path"] = out["file"]["path"] or _extract_kv(log_line, "dst") or _extract_kv(log_line, "artifact_path")

        if not out["event_type"]:
            m = re.search(
                r"\b(DVWA_UPLOAD_MOVE|ARTIFACT_WRITE|ARTIFACT_WRITE_SUSP_EXT|ARTIFACT_WRITE_ARCHIVE|ARTIFACT_FETCH_TO_UPLOAD)\b",
                log_line,
            )
            if m:
                out["event_type"] = m.group(1)

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


def exec_in_pod(v1: client.CoreV1Api, namespace: str, pod: str, container: str, cmd: str) -> str:
    return stream(
        v1.connect_get_namespaced_pod_exec,
        pod,
        namespace,
        container=container,
        command=["sh", "-c", cmd],
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
        _preload_content=True,
    )


def send_discord(webhook_url: str, payload: dict) -> dict:
    """
    Discord webhook으로 메시지 전송.
    - 실패(403 포함)해도 예외를 던지지 않고 상태를 반환.
    - Discord는 HTTP API 호출 시 유효한 User-Agent가 없으면 차단될 수 있다고 명시. [web:53]
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://example.com/5entinel, 1.0)",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:800]
        except Exception:
            pass
        return {"ok": False, "status": e.code, "body": err_body}
    except Exception as e:
        return {"ok": False, "status": None, "error": str(e)}


def lambda_handler(event, context):
    cluster_name = os.environ.get("EKS_CLUSTER_NAME", CLUSTER_NAME)
    quarantine_dir = os.environ.get("QUARANTINE_DIR", DEFAULT_QUAR_DIR)
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")

    norm = normalize_input(event)
    ns = norm["k8s"]["namespace"]
    pod = norm["k8s"]["pod"]
    container = norm["k8s"]["container"]
    src_path = norm["file"]["path"]
    sha256 = norm["extract"]["sha256"]
    event_type = norm["event_type"]

    def _discord_report(status: str, extra_fields: list[dict], short_content: str | None = None):
        if not webhook_url:
            return {"skipped": True}

        base = src_path.split("/")[-1] if src_path else "unknown"

        embed = {
            "title": f"SOAR File Delay - {status}",
            "description": "Falco 파일 이벤트 기반 격리(이동/이름변경) 리포트",
            "fields": [
                {"name": "Cluster", "value": str(cluster_name), "inline": True},
                {"name": "EventType", "value": str(event_type), "inline": True},
                {"name": "Namespace", "value": str(ns), "inline": True},
                {"name": "Pod", "value": str(pod), "inline": False},
                {"name": "Container", "value": str(container), "inline": False},
                {"name": "FileName", "value": str(base), "inline": False},
                {"name": "SrcPath", "value": str(src_path), "inline": False},
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        for f in (extra_fields or []):
            if isinstance(f, dict) and "name" in f and "value" in f:
                embed["fields"].append(
                    {"name": str(f["name"]), "value": str(f["value"]), "inline": bool(f.get("inline", False))}
                )

        payload = {"username": "5entinel-siem", "embeds": [embed]}
        if short_content:
            payload["content"] = short_content

        result = send_discord(webhook_url, payload)
        if not result.get("ok"):
            print({"discord_send_failed": result})
        return result

    missing = [k for k, v in {"namespace": ns, "pod": pod, "container": container, "src_path": src_path}.items() if not v]
    if missing:
        _discord_report(
            "FAIL",
            [
                {"name": "Reason", "value": "missing_required_fields"},
                {"name": "Missing", "value": ",".join(missing)},
            ],
            short_content="SOAR file delay FAIL (missing fields)",
        )
        return {"delayed": False, "reason": "missing_required_fields", "missing": missing, "normalized": norm, "cluster": cluster_name}

    if not sha256:
        sha256 = hashlib.sha256(src_path.encode("utf-8")).hexdigest()

    base = src_path.split("/")[-1] if src_path else "unknown"
    safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    new_name = f"quarantine_{sha256[:12]}_{safe_base}"
    dst_path = f"{quarantine_dir}/{new_name}"

    try:
        api_client = build_k8s_api_client(cluster_name)
        v1 = client.CoreV1Api(api_client)
    except Exception as e:
        _discord_report(
            "FAIL",
            [
                {"name": "Reason", "value": "k8s_client_init_failed"},
                {"name": "Error", "value": str(e)},
            ],
            short_content="SOAR file delay FAIL (k8s client init)",
        )
        return {"delayed": False, "reason": "k8s_client_init_failed", "error": str(e), "normalized": norm, "cluster": cluster_name}

    cmd = (
        f"set -e; "
        f"if [ ! -f '{src_path}' ]; then echo 'NOFILE'; exit 0; fi; "
        f"mkdir -p '{quarantine_dir}'; "
        f"mv -f '{src_path}' '{dst_path}'; "
        f"echo 'MOVED:{dst_path}'"
    )

    try:
        out = exec_in_pod(v1, ns, pod, container, cmd)
    except Exception as e:
        _discord_report(
            "FAIL",
            [
                {"name": "Reason", "value": "k8s_exec_failed"},
                {"name": "Error", "value": str(e)},
                {"name": "DstPath", "value": dst_path},
            ],
            short_content="SOAR file delay FAIL (k8s exec)",
        )
        return {"delayed": False, "reason": "k8s_exec_failed", "error": str(e), "normalized": norm, "cluster": cluster_name}

    lowered = (out or "").lower()

    if "nofile" in lowered:
        _discord_report(
            "FAIL",
            [
                {"name": "Reason", "value": "file_not_found"},
                {"name": "DstPath", "value": dst_path},
            ],
            short_content="SOAR file delay FAIL (file not found)",
        )
        return {
            "delayed": False,
            "reason": "file_not_found",
            "src_path": src_path,
            "dst_path": dst_path,
            "normalized": norm,
            "k8s_exec_output": (out or "")[:500],
            "cluster": cluster_name,
        }

    if "moved:" in lowered:
        m = re.search(r"moved:(.+)$", out.strip(), flags=re.IGNORECASE)
        moved_to = m.group(1).strip() if m else dst_path

        _discord_report(
            "OK",
            [
                {"name": "MoveTo", "value": moved_to},
                {"name": "RenameTo", "value": new_name},
                {"name": "QuarantineDir", "value": quarantine_dir},
                {"name": "SHA256", "value": sha256},
            ],
            short_content=f"SOAR file delay OK: {base} -> {new_name}",
        )

        return {
            "delayed": True,
            "action": "mv_rename",
            "event_type": event_type,
            "src_path": src_path,
            "dst_path": moved_to,
            "new_name": new_name,
            "quarantine_dir": quarantine_dir,
            "sha256": sha256,
            "cluster": cluster_name,
            "normalized": norm,
        }

    _discord_report(
        "FAIL",
        [
            {"name": "Reason", "value": "unexpected_exec_output"},
            {"name": "DstPath", "value": dst_path},
            {"name": "ExecOut", "value": (out or "")[:200]},
        ],
        short_content="SOAR file delay FAIL (unexpected exec output)",
    )
    return {
        "delayed": False,
        "reason": "unexpected_exec_output",
        "src_path": src_path,
        "dst_path": dst_path,
        "normalized": norm,
        "k8s_exec_output": (out or "")[:500],
        "cluster": cluster_name,
    }

import os
import json
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple, Optional

import boto3
from botocore.exceptions import ClientError


ec2 = boto3.client("ec2")

DEFAULT_NACL_ID = "your_nacl_id"
DEFAULT_RULE_START = 100
DEFAULT_RULE_STEP = 10
DEFAULT_RULE_MAX = 2000  # 룰이 많아지면 확장/정리 필요

# Discord Embed colors are integers (decimal). [web:98]
COLOR_GREEN = 3066993
COLOR_YELLOW = 16776960
COLOR_RED = 15158332


def _get_str(d: Dict[str, Any], key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Missing/invalid '{key}'")
    return v.strip()


def _get_int(d: Dict[str, Any], key: str) -> int:
    v = d.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"Missing/invalid '{key}' (must be int)")
    return v


def _normalize_ip_to_cidr32(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip.version != 4:
        raise ValueError("Only IPv4 is supported for this handler.")
    return f"{ip_str}/32"


def _describe_nacl(nacl_id: str) -> Dict[str, Any]:
    resp = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    acls = resp.get("NetworkAcls", [])
    if not acls:
        raise ValueError(f"NACL not found: {nacl_id}")
    return acls[0]


def _entry_key(e: Dict[str, Any]) -> Tuple:
    pr = e.get("PortRange") or {}
    return (
        bool(e.get("Egress")),
        str(e.get("Protocol")),
        e.get("RuleAction"),
        e.get("CidrBlock"),
        pr.get("From"),
        pr.get("To"),
    )


def _existing_rule_numbers(entries: List[Dict[str, Any]], egress: bool) -> Set[int]:
    out: Set[int] = set()
    for e in entries:
        if bool(e.get("Egress")) == egress and "RuleNumber" in e:
            out.add(int(e["RuleNumber"]))
    return out


def _find_free_rule_number(used: Set[int]) -> int:
    for rn in range(DEFAULT_RULE_START, DEFAULT_RULE_MAX + 1, DEFAULT_RULE_STEP):
        if rn not in used:
            return rn
    raise RuntimeError("No free RuleNumber found in the configured range.")


def _discord_post(webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "5entinel-lambda/1.1"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            # Discord webhook execute returns 204 No Content by default. [web:100]
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = ""
        return {"ok": False, "status": e.code, "error_body": err_body}
    except Exception as e:
        return {"ok": False, "status": None, "error": str(e)}


def _pick_color(status: str) -> int:
    if status == "created":
        return COLOR_GREEN
    if status == "already_exists":
        return COLOR_YELLOW
    return COLOR_RED


def _extract_k8s_meta(falco: Optional[Dict[str, Any]]) -> Dict[str, str]:
    pod = "-"
    ns = "-"
    host = "-"

    if isinstance(falco, dict):
        k8s = falco.get("kubernetes") or {}
        if isinstance(k8s, dict):
            pod = (k8s.get("pod_name") or k8s.get("k8s_pod_name") or "-")
            ns = (k8s.get("namespace_name") or k8s.get("k8s_ns_name") or "-")
            host = (k8s.get("host") or "-")

    return {"pod": str(pod), "ns": str(ns), "host": str(host)}


def _build_discord_embed_payload(
    status: str,
    nacl_id: str,
    rule_number: int,
    cidr: str,
    port: int,
    falco: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    k8s = _extract_k8s_meta(falco)

    # Webhook can send embeds with rich fields. [web:100]
    embed = {
        "title": "NACL Egress 차단 적용",
        "color": _pick_color(status),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields": [
            {"name": "상태", "value": status, "inline": True},
            {"name": "NACL", "value": nacl_id, "inline": True},
            {"name": "룰번호", "value": str(rule_number), "inline": True},
            {"name": "대상", "value": cidr, "inline": True},
            {"name": "포트", "value": f"TCP/{port}", "inline": True},
            {"name": "K8S", "value": f"ns={k8s['ns']}\npod={k8s['pod']}\nhost={k8s['host']}", "inline": False},
        ],
        "footer": {"text": "5entinel SOAR"},
    }

    payload = {
        # content 없이 embeds만 보내도 됨. [web:100]
        "username": "5entinel",
        "embeds": [embed],
        # 실수로 @everyone 등이 나가면 곤란하니 기본적으로 멘션 비활성화
        "allowed_mentions": {"parse": []},
    }
    return payload


def _send_discord_best_effort(
    webhook_url: str,
    status: str,
    nacl_id: str,
    rule_number: int,
    cidr: str,
    port: int,
    falco: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not webhook_url:
        return {"ok": False, "reason": "skipped_no_webhook"}

    payload = _build_discord_embed_payload(
        status=status,
        nacl_id=nacl_id,
        rule_number=rule_number,
        cidr=cidr,
        port=port,
        falco=falco,
    )
    return _discord_post(webhook_url, payload)


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    nacl_id = os.environ.get("NACL_ID", DEFAULT_NACL_ID)
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()

    attacker_ip = _get_str(event, "attacker_ip")
    attacker_port = _get_int(event, "attacker_port")
    falco = event.get("falco") if isinstance(event.get("falco"), dict) else None

    if attacker_port < 1 or attacker_port > 65535:
        raise ValueError(f"Invalid attacker_port: {attacker_port}")

    cidr_32 = _normalize_ip_to_cidr32(attacker_ip)

    nacl = _describe_nacl(nacl_id)
    entries = nacl.get("Entries", [])

    desired_k = (
        True,      # Egress
        "6",       # TCP protocol number
        "deny",
        cidr_32,
        attacker_port,
        attacker_port,
    )

    # 1) 이미 동일 규칙이 있으면 "already_exists"로 처리하고 Discord는 best-effort
    for e in entries:
        if _entry_key(e) == desired_k:
            rule_no = int(e["RuleNumber"])
            result: Dict[str, Any] = {
                "status": "already_exists",
                "network_acl_id": nacl_id,
                "rule_number": rule_no,
                "cidr": cidr_32,
                "protocol": "tcp",
                "port": attacker_port,
            }

            result["discord"] = _send_discord_best_effort(
                webhook_url=webhook_url,
                status=result["status"],
                nacl_id=nacl_id,
                rule_number=rule_no,
                cidr=cidr_32,
                port=attacker_port,
                falco=falco,
            )
            return result

    # 2) 없으면 새 RuleNumber를 찾아 생성(누적)
    used = _existing_rule_numbers(entries, egress=True)
    rule_number = _find_free_rule_number(used)

    try:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number,
            Protocol="6",
            RuleAction="deny",
            Egress=True,
            CidrBlock=cidr_32,
            PortRange={"From": attacker_port, "To": attacker_port},
        )
    except ClientError as e:
        # 경합으로 같은 룰번호를 누가 먼저 쓰면 1회 재시도
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NetworkAclEntryAlreadyExists", "InvalidNetworkAclEntry.DuplicateRuleNumber"):
            nacl = _describe_nacl(nacl_id)
            used = _existing_rule_numbers(nacl.get("Entries", []), egress=True)
            rule_number = _find_free_rule_number(used)
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Protocol="6",
                RuleAction="deny",
                Egress=True,
                CidrBlock=cidr_32,
                PortRange={"From": attacker_port, "To": attacker_port},
            )
        else:
            raise

    result = {
        "status": "created",
        "network_acl_id": nacl_id,
        "rule_number": rule_number,
        "cidr": cidr_32,
        "protocol": "tcp",
        "port": attacker_port,
    }

    # 3) Discord는 best-effort: 실패해도 Lambda는 성공 반환(워크플로우 진행)
    result["discord"] = _send_discord_best_effort(
        webhook_url=webhook_url,
        status=result["status"],
        nacl_id=nacl_id,
        rule_number=rule_number,
        cidr=cidr_32,
        port=attacker_port,
        falco=falco,
    )

    return result

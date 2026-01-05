import json
import re
from typing import Any, Dict


IP_RE = re.compile(r"Attacker_IP:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
PORT_RE = re.compile(r"Attacker_Port:\s*([0-9]{1,5})")


def _get_log_string(event: Dict[str, Any]) -> str:
    # Step Functions에서 Payload로 $.falco 를 넘기므로, event는 falco object일 가능성이 큼
    # 그래도 방어적으로 두 필드를 모두 확인
    for key in ("log",):
        if isinstance(event.get(key), str) and event[key].strip():
            return event[key]
    raw = event.get("raw_message", {})
    if isinstance(raw, dict) and isinstance(raw.get("log"), str):
        return raw["log"]
    raise ValueError("No log string found in event (expected 'log' or 'raw_message.log').")


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid port: {port}")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    log_line = _get_log_string(event)

    ip_m = IP_RE.search(log_line)
    port_m = PORT_RE.search(log_line)

    if not ip_m or not port_m:
        raise ValueError("Reverse shell IoC parse failed (Attacker_IP / Attacker_Port not found).")

    attacker_ip = ip_m.group(1)
    attacker_port = int(port_m.group(1))
    _validate_port(attacker_port)

    return {
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "matched": "ARTIFACT_Reverse_Shell_Suspected!"
    }

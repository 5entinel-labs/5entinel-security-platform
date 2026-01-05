import os
import json
import urllib.request
import urllib.error
import urllib.parse
import boto3

sfn = boto3.client("stepfunctions")

DISCORD_WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]
API_GATEWAY_URL = os.environ["API_GATEWAY_URL"]


def _pick(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def lambda_handler(event, context):
    task_token = event.get("token")
    if not task_token:
        print("Error: Task Token missing in event")
        return {"statusCode": 400, "body": "Missing Task Token"}

    falco_data = event.get("falco", {})
    log_msg = _pick(falco_data, ["log"]) or _pick(falco_data, ["raw_message", "log"]) or "Unknown Event"

    # 1. 로그 길이 안전하게 자르기
    log_summary = str(log_msg)[:800]

    # 2. URL 생성 (토큰 URL 인코딩)
    encoded_token = urllib.parse.quote(task_token, safe="")  # 토큰을 쿼리스트링에 넣을 때 인코딩 [web:68]
    approve_link = f"{API_GATEWAY_URL}?action=allow&taskToken={encoded_token}"
    deny_link = f"{API_GATEWAY_URL}?action=block&taskToken={encoded_token}"

    # 3. 백틱(코드펜스)
    CB = "```"

    # 4. Description에는 로그만
    description_text = f"**Event Log:**\n{CB}json\n{log_summary}\n{CB}"

    # 5. 링크를 '하이퍼링크(마스킹 링크)'로 표시 + URL은 <...>로 감싸 노출 최소화[2][1]
    payload = {
        "content": "⚠️ **Suspicious Activity Detected!** Approval Required.",
        "embeds": [
            {
                "title": "👮‍♂️ Admin Intervention Needed",
                "description": description_text,
                "color": 0xFFAA00,
                "fields": [
                    {
                        "name": "✅ Approve",
                        "value": f"[Click to Allow]({approve_link})",
                        "inline": False
                    },
                    {
                        "name": "🛑 Deny",
                        "value": f"[Click to Block]({deny_link})",
                        "inline": False
                    },
                ],
                "footer": {"text": "Links contain secure tokens. Do not share."},
            }
        ],
    }

    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print("Sent approval request to Discord")
            return {"status": "Waiting for admin...", "statusCode": resp.status}
    except urllib.error.HTTPError as e:
        print(f"Discord API Error: {e.code} - {e.read().decode()}")
        raise e

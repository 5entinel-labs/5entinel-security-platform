import boto3
import requests
import time
import os
import json
import subprocess
import traceback
import google.generativeai as genai
from datetime import datetime

# ================= 1. 환경 설정 =================
S3_QUARANTINE   = "quarantine-cuckoo"
S3_DASHBOARD    = "dashboard-index"
AWS_REGION      = "us-east-1"                 

CUCKOO_URL      = "http://localhost:8090"
DISCORD_URL     = ""
GEMINI_API_KEY  = "" 

DOWNLOAD_PATH   = "/tmp/cuckoo_downloads"
YARA_RULES_FILE = "rules.yar"
YARA_BINARY_PATH = "yara" 

MAX_WAIT_TIME   = 300
# =================================================

# AI 설정
try:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')
except:
    print("Gemini 설정 실패 (API Key 확인 필요)")

# AWS 설정
try:
    s3 = boto3.client('s3', region_name=AWS_REGION)
except:
    print("AWS 설정 오류")
    exit()

# --- 도구 모듈 ---

def run_yara_external(target_path):
    """
    외부 실행 파일을 호출하여 YARA 스캔을 수행하고 결과를 파싱함
    """
    formatted = []
    total_match_count = 0
    global YARA_BINARY_PATH, YARA_RULES_FILE
    
    try:
        cmd = [YARA_BINARY_PATH, "-m", "-s", "-g", YARA_RULES_FILE, target_path]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode != 0 and not result.stdout:
            print(f"YARA 실행 실패: {result.stderr}")
            return formatted, 0

        lines = result.stdout.splitlines()
        current_rule = None

        print(f"\n[YARA 정적 분석 결과: {os.path.basename(target_path)}]")
        print("-" * 50)

        for line in lines:
            line = line.strip()
            if not line: continue
            
            if not line.startswith("0x"):
                parts = line.split()
                if not parts: continue
                
                rule_name = parts[0]
                total_match_count += 1
                
                severity = "Warning"
                if any(kw in rule_name.lower() for kw in ['malware', 'webshell', 'critical', 'trojan', 'ransomware']):
                    severity = "Critical"
                
                color_code = "\033[91m" if severity == "Critical" else "\033[93m" # 빨강/노랑
                reset_code = "\033[0m"
                print(f"탐지됨: {color_code}{rule_name}{reset_code} [{severity}]")
                # -----------------------

                current_rule = {
                    "rule_name": rule_name,
                    "severity": severity,
                    "description": f"정적 분석 탐지 규칙: {rule_name}",
                    "match_data": "N/A",
                    "offset": "N/A"
                }
                formatted.append(current_rule)
            
            elif line.startswith("0x") and current_rule:
                try:
                    detail_parts = line.split(':', 2)
                    if len(detail_parts) >= 2:
                        current_rule["offset"] = detail_parts[0].strip()
                        current_rule["match_data"] = detail_parts[2].strip() if len(detail_parts) > 2 else detail_parts[1].strip()
                        print(f"   └─ Offset: {current_rule['offset']}, Match: {current_rule['match_data'][:50]}")
                except: pass

        score = min((60 + total_match_count * 2) / 10.0, 10.0) if total_match_count > 0 else 0.0
        print("-" * 50)
        return formatted, score
    except Exception as e:
        print(f"YARA 스캔 중 오류 발생: {e}")
        return formatted, 0

def extract_cuckoo_yara(report_json):
    """Cuckoo 리포트 JSON에서 YARA 매칭 정보 추출"""
    yara_results = []
    try:
        yara_data = report_json.get("target", {}).get("file", {}).get("yara", [])
        for match in yara_data:
            name = match.get("name", "Unknown Rule")
            meta = match.get("meta", {})
            severity = meta.get("severity") or meta.get("priority") or "N/A"
            
            match_str = 'N/A'
            offset = 'N/A'
            strings = match.get("strings")
            if strings and isinstance(strings, list) and len(strings) > 0:
                offset = hex(strings[0].get("offset", 0))
                match_str = strings[0].get("data") or strings[0].get("string") or 'N/A'

            yara_results.append({
                "rule_name": name,
                "severity": str(severity).title(),
                "description": meta.get("description", "Cuckoo 행위 기반 탐지"),
                "match_data": match_str,
                "offset": offset
            })
    except: pass
    return yara_results

def upload_to_dashboard(filename, score, status, task_id, report_url=None, ai_summary="", yara_matches=[]):
    """대시보드 업데이트용 JSON 생성 및 S3 업로드"""
    try:
        data = {
            "timestamp": datetime.now().isoformat(),
            "filename": filename, 
            "score": score, 
            "task_id": task_id,
            "status": status, 
            "message": f"현 상태: {status}",
            "report_url": report_url, 
            "ai_summary": ai_summary, 
            "yara": yara_matches
        }
        s3.put_object(
            Bucket=S3_DASHBOARD, 
            Key="latest.json", 
            Body=json.dumps(data), 
            ContentType="application/json", 
            CacheControl="no-cache"
        )
        print(f"대시보드 업데이트 완료 ({status})")
    except Exception as e:
        print(f"대시보드 업데이트 실패: {e}")

def get_ai_summary(signatures, score):
    """Gemini AI를 활용한 분석 결과 3줄 요약"""
    try:
        if not signatures: return "특이 행위가 발견되지 않았음"
        
        sig_list = [s['description'] for s in signatures[:10]]
        prompt = f"""
        다음 악성코드 행위 로그를 분석하여 핵심만 간결하게 3줄로 요약하라
        '보고합니다' 같은 서두는 생략하고 팩트 위주로 '~함/임'체로 종결할 것

        [제약 사항]
        1 강조를 위한 '**' 표시나 마크다운 문법을 절대 사용하지 말 것
        
        [분석 데이터]
        위험도: {score}/10
        행위 목록: {sig_list}
        
        [출력 형식]
        1. 식별: (주요 행위 요약)
        2. 위험: (핵심 위험성)
        3. 대응: (권장 조치)
        """
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"AI 요약 실패: {e}")
        return "AI 분석 서버 연결 불가"

def upload_report_to_s3(task_id, filename):
    """Cuckoo 리포트를 S3에 업로드하고 URL 반환"""
    local_path = os.path.join(os.path.expanduser("~/.cuckoo/storage/analyses"), str(task_id), "reports", "report.html")
    if os.path.exists(local_path):
        try:
            ts = int(time.time())
            key = f"reports/{filename}_{ts}.html"
            s3.upload_file(local_path, S3_DASHBOARD, key, ExtraArgs={'ContentType': 'text/html'})
            domain = "s3.amazonaws.com" if AWS_REGION == "us-east-1" else f"s3.{AWS_REGION}.amazonaws.com"
            url = f"https://{S3_DASHBOARD}.{domain}/{key}"
            print(f"리포트 업로드 완료: {url}")
            return url
        except Exception as upload_err:
            print(f"S3 리포트 업로드 실패: {upload_err}")
            return None
        time.sleep(1)
    
    print(f"리포트 파일을 찾을 수 없음: {local_path}")
    return None

def send_discord(filename, score, task_id, report_url, ai_summary, yara_matches):
    current_score = score if score is not None else 0
    color = 0xFF0000 if score >= 7 else 0xFFA500 if score >= 4 else 0x00FF00
    
    if yara_matches:
        yara_lines = []
        for y in yara_matches:
            line = f"**{y['rule_name']}** (Sev: {y['severity']})"
            yara_lines.append(line)
        yara_text = "\n".join(yara_lines)
    else:
        yara_text = "탐지된 YARA 룰 없음 (Clean)"

    if len(yara_text) > 1000: yara_text = yara_text[:950] + "\n...(생략)"
    if len(ai_summary) > 1000: ai_summary = ai_summary[:1000] + "..."

    embed = {
        "title": f"분석 보고: {filename}",
        "color": color,
        "fields": [
            {"name": "위험도 점수", "value": f"**{current_score} / 10.0**", "inline": True},
            {"name": "YARA 탐지", "value": yara_text, "inline": False},
            {"name": "AI 요약 및 상태", "value": ai_summary if ai_summary else "요약 없음", "inline": False}
        ],
        "footer": {"text": f"Task ID: {task_id}"}
    }

    if report_url:
        embed["url"] = report_url

    try:
        res = requests.post(DISCORD_URL, json={"username": "AI 5entinel", "embeds": [embed]})
        print(f"디스코드 전송 결과: {res.status_code}") 
    except Exception as e:
        print(f"디스코드 전송 실패: {e}")

# --- 메인 파이프라인 ---

def process_file(file_key):
    local_path = os.path.abspath(os.path.join(DOWNLOAD_PATH, file_key))
    start_time = time.time()
    task_id = 0
    
    try:
        print(f"\n파일 처리 시작: {file_key}")
        s3.download_file(S3_QUARANTINE, file_key, local_path)

        # 1. YARA 분석
        local_yara_matches, detection_score = run_yara_external(local_path)
        upload_to_dashboard(file_key, detection_score, "yara_complete", 0, yara_matches=local_yara_matches)

        # 2. Cuckoo 분석 요청
        print("Cuckoo 샌드박스로 정밀 분석 요청 중...")
        with open(local_path, "rb") as f:
            res = requests.post(f"{CUCKOO_URL}/tasks/create/file", files={"file": (file_key, f)}, timeout=15)
            task_id = res.json().get("task_id")

        while time.time() - start_time < MAX_WAIT_TIME:
            stat_res = requests.get(f"{CUCKOO_URL}/tasks/view/{task_id}").json()
            status = stat_res.get("task", {}).get("status")
            if status == "reported": break
            if status in ["failed", "exception"]: raise Exception(f"Cuckoo 분석 실패: {status}")
            time.sleep(10)
        
        # 4. 리포트 파싱 및 최종 업데이트
        report_json = requests.get(f"{CUCKOO_URL}/tasks/report/{task_id}", timeout=15).json()
        final_score = report_json.get("info", {}).get("score", detection_score)
        ai_summary = get_ai_summary(report_json.get("signatures", []), final_score)
        
        report_url = upload_report_to_s3(task_id, file_key)
        final_yara = local_yara_matches + extract_cuckoo_yara(report_json)

        upload_to_dashboard(file_key, final_score, "COMPLETE", task_id, report_url=report_url, ai_summary=ai_summary, yara_matches=final_yara)
        send_discord(file_key, final_score, task_id, report_url, ai_summary, final_yara)
        print(f"분석 종료 (Score: {final_score})")

    except Exception as e:
        print(f"분석 실패: {e}")
        upload_to_dashboard(file_key, 0, "ERROR", task_id, ai_summary=f"오류 발생: {str(e)}")

def main():
    if not os.path.exists(DOWNLOAD_PATH): os.makedirs(DOWNLOAD_PATH)
    processed = set()
    print("S.H.I.E.L.D 통합 브릿지 서버 가동 중")
  
    try:
        initial_objs = s3.list_objects_v2(Bucket=S3_QUARANTINE)
        if 'Contents' in initial_objs:
            for obj in initial_objs['Contents']:
                processed.add(obj['Key'])
            print(f"초기 스캔 완료: 기존 파일 {len(processed)}개 무시 설정됨")
    except Exception as e:
        print(f"초기 스캔 오류 (무시하고 진행): {e}")

    while True:
        try:
            res = s3.list_objects_v2(Bucket=S3_QUARANTINE)
            if 'Contents' in res:
                sorted_files = sorted(res['Contents'], key=lambda x: x['LastModified'])
                for obj in sorted_files:
                    file_key = obj['Key']
                    if file_key not in processed:
                        process_file(file_key)
                        processed.add(file_key)
            time.sleep(5)
        except Exception as e:
            print(f"루프 에러: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()

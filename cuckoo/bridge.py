import boto3
import requests
import time
import os
import json
import traceback
import google.generativeai as genai
from datetime import datetime
import yara

# ================= 설정 =================
S3_QUARANTINE   = "quarantine-cuckoo"
S3_DASHBOARD    = "dashboard-index"
AWS_REGION      = "us-east-1"                 
CUCKOO_URL      = "http://localhost:8090"
DISCORD_URL   = "discord webhook"
DOWNLOAD_PATH   = "/tmp/cuckoo_downloads"
GEMINI_API_KEY  = "api key" 
CUCKOO_STORAGE_PATH = os.path.expanduser("~/.cuckoo/storage/analyses")
YARA_RULES_FILE = "rules.yar"
# ===================================================

# AI 설정
try:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')
except:
    print("Gemini 설정 실패 (API Key 확인 필요)")

try:
    s3 = boto3.client('s3', region_name=AWS_REGION)
except:
    print("AWS 설정 오류")
    exit()

try:
    if os.path.exists(YARA_RULES_FILE):
        yara_rules = yara.compile(filepath=YARA_RULES_FILE)
        print(f"YARA 룰 로딩 완료: {YARA_RULES_FILE}")
    else:
        yara_rules = None
        print(f"YARA 룰 파일 없음 ({YARA_RULES_FILE}) - 정적 분석 건너뜀")
except Exception as e:
    print(f"YARA 룰 오류: {e}")
    yara_rules = None


def get_ai_summary(signatures, score):
    """Gemini에게 분석 결과 요약을 요청 (간결한 버전)"""
    try:
        if not signatures:
            return "특이 행위가 발견되지 않았음."
            
        sigs = [s['description'] for s in signatures[:10]] 
        
        prompt = f"""
        다음 악성코드 행위 로그를 분석하여 핵심만 간결하게 3줄로 요약하라.
        '보고합니다' 같은 서두나 인사말은 생략하고, 팩트 위주로 '~함/임'체로 종결할 것.

        [제약 사항]
        1. 텍스트 강조를 위한 '**' 표시나 마크다운 문법을 절대 사용하지 말 것.
        
        [분석 데이터]
        위험도: {score}/10
        행위 목록: {sigs}
        
        [출력 형식]
        1. 식별: (주요 행위 및 의도 간략 요약)
        2. 위험: (핵심 위험성)
        3. 대응: (권장 조치)
        """
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"AI 요약 실패: {e}")
        return "AI 분석 서버 연결 불가"

def format_local_yara_matches(matches):
    """
    로컬 YARA 매칭 결과(yara-python 객체)를 
    대시보드 전송용 딕셔너리 리스트로 변환 (상세 정보 포함)
    """
    formatted = []
    for match in matches:
        meta = match.meta if hasattr(match, 'meta') else {}
        
        severity = meta.get('severity', 'Informational').title() 
        description = meta.get('description', f"룰 {match.rule}의 정적 분석 탐지 결과")

        tags_list = match.tags if match.tags else ["static_analysis"]
        tags_str = ", ".join(tags_list)

        match_data = 'N/A' 
        offset = 'N/A'     

        if match.strings:
            try:
                is_valid_data_found = False
                for item in match.strings:
                    match_offset = None
                    raw_data = None
                    
                    # 1. 객체 속성 확인 (yara.StringMatch)
                    if hasattr(item, 'offset') and hasattr(item, 'data'):
                        match_offset = item.offset
                        raw_data = item.data
                    # 2. 튜플 구조 확인
                    elif isinstance(item, tuple) and len(item) >= 3:
                        match_offset = item[0]
                        raw_data = item[2]
                        
                    if match_offset is not None and raw_data is not None:
                        offset = hex(match_offset)
                        
                        if isinstance(raw_data, bytes):
                            try:
                                decoded_data = raw_data.decode('utf-8', errors='strict').strip()
                            except UnicodeDecodeError:
                                decoded_data = raw_data.decode('latin-1', errors='replace').strip()
                            
                            match_data = decoded_data if decoded_data else raw_data.hex()
                        else:
                            match_data = str(raw_data)
                        
                        is_valid_data_found = True
                        break 
                    
                if not is_valid_data_found:
                    match_data = f"YARA 상세 추출 실패: 매치 데이터 구조 오류 (오프셋/데이터 누락)"
            
            except Exception as e:
                # 추출 과정 중 예상치 못한 에러 발생 시
                offset = "N/A"
                match_data = f"YARA 추출 중 치명적 에러: {type(e).__name__} - {str(e)}"
        
        else:
            # strings 섹션이 없는 룰 처리 (FileType_Text 등)
            if severity.lower() == 'informational': 
                match_data = "N/A (파일 속성 기반 룰은 매치 문자열이 없습니다)"
                offset = "N/A"
            else:
                 # strings 섹션이 없는데 심각도가 높다면 오류 처리
                 match_data = "YARA 오류: strings 없이 탐지되었으나 상세 정보 추출 실패"
                 offset = "N/A"

        formatted.append({
            "rule_name": match.rule,        
            "severity": severity,
            "tags": tags_str,
            "description": description,
            "match_data": match_data[:100] + "..." if len(match_data) > 100 else match_data, 
            "offset": offset,               
        })
    return formatted

def extract_cuckoo_yara(report_json):
    """Cuckoo 리포트 JSON에서 YARA 매칭 정보 추출 (필드 간소화 적용)"""
    yara_results = []
    try:
        yara_data = report_json.get("target", {}).get("file", {}).get("yara", [])
        
        for match in yara_data:
            name = match.get("name", "Unknown Rule")
            meta = match.get("meta", {})
            tags = match.get("tags", [])
            tags_str = ", ".join(tags) if tags else "-"

            severity = meta.get("severity") or meta.get("priority") or "N/A"
            description = meta.get("description", "Cuckoo를 통한 동적/정적 분석 탐지 결과.")

            match_data = 'N/A' 
            offset = 'N/A'     
            
            strings = match.get("strings")
            if strings and isinstance(strings, list) and len(strings) > 0:
                first_match = strings[0]
                offset = hex(first_match.get("offset", 0))
                
                data_field = first_match.get("data") or first_match.get("plaintext") or first_match.get("string")
                match_data = data_field if data_field else 'N/A'

            yara_results.append({
                "rule_name": name,                      
                "severity": str(severity).title(), 
                "tags": tags_str,
                "description": description,
                "match_data": match_data,               
                "offset": offset,                       
            })
    except Exception as e:
        print(f"Cuckoo YARA 파싱 중 오류: {e}")
        
    return yara_results

def upload_report_to_s3(task_id, filename):
    local_path = os.path.join(CUCKOO_STORAGE_PATH, str(task_id), "reports", "report.html")
    for i in range(10):
        if os.path.exists(local_path):
            try:
                ts = int(time.time())
                key = f"reports/{filename}_{ts}.html"
                s3.upload_file(local_path, S3_DASHBOARD, key, ExtraArgs={'ContentType': 'text/html'})
                domain = "s3.amazonaws.com" if AWS_REGION == "us-east-1" else f"s3.{AWS_REGION}.amazonaws.com"
                return f"https://{S3_DASHBOARD}.{domain}/{key}"
            except: return None
        time.sleep(1)
    return None

def upload_to_dashboard(filename, score, status, task_id, report_url=None, ai_summary="", yara_matches=[]):
    try:
        if status == "yara_complete":
            msg = "정적 분석(YARA) 완료. 동적 분석(Cuckoo) 대기 중..."
            d_score = 0
        elif status == "analyzing":
            msg = "샌드박스 정밀 분석 중..."
            d_score = 0
        else:
            msg = f"위험도 분석 완료 ({score}/10.0)"
            d_score = score

        data = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "filename": filename,
            "score": d_score,
            "task_id": task_id,
            "status": status,
            "message": msg,
            "report_url": report_url,
            "ai_summary": ai_text if (ai_text := ai_summary) else "",
            "yara": yara_matches 
        }
        
        s3.put_object(
            Bucket=S3_DASHBOARD, Key="latest.json", Body=json.dumps(data),
            ContentType="application/json", CacheControl="no-cache"
        )
        print(f"대시보드 업데이트 ({status})")
    except Exception as e:
        print(f"대시보드 실패: {e}")

def send_discord(filename, score, task_id, report_url, ai_summary, yara_matches):
    current_score = score if score is not None else 0
    color = 0xFF0000 if score >= 7 else 0xFFA500 if score >= 4 else 0x00FF00
    
    if yara_matches:
        yara_lines = []
        for y in yara_matches:
            line = f"**{y['rule_name']}** (Sev: {y['severity']} | Tags: {y['tags']})"
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

def process_file(file_key):
    local_path = os.path.join(DOWNLOAD_PATH, file_key)
    task_id = None
    
    local_yara_matches = []
    cuckoo_yara_matches = []
    file_content = None

    # 최대 대기 시간 설정 (6분 = 360초)
    MAX_WAIT_TIME = 360
    start_time = time.time()
    last_status = "submitted" 

    try:
        print(f"다운로드: {file_key}")
        s3.download_file(S3_QUARANTINE, file_key, local_path)

        if os.path.exists(local_path):
            with open(local_path, "rb") as f:
                file_content = f.read()
        
        # 1. 로컬 YARA 스캔 수행 및 '저장'
        if yara_rules and file_content:
            try:
                matches = yara_rules.match(data=file_content)
                local_yara_matches = format_local_yara_matches(matches)
                match_names = [m['rule_name'] for m in local_yara_matches]
                print(f"로컬 YARA 탐지: {match_names if match_names else 'Clean'}")
            except Exception as e:
                print(f"로컬 YARA 스캔 에러: {e}")

        # 2. Cuckoo 분석 요청
        print(f"분석 시작...")
        with open(local_path, "rb") as f:
            r = requests.post(f"{CUCKOO_URL}/tasks/create/file", files={"file": (file_key, f)})
            task_id = r.json().get("task_id")

        # 분석 요청 후 로컬 YARA 결과만 담아 1차 업데이트 (상태: yara_complete)
        upload_to_dashboard(file_key, 0, "yara_complete", task_id, yara_matches=local_yara_matches)
        
        # 3. 결과 리포트 대기 루프 (타임아웃 적용 및 상태 변경 시만 업데이트)
        while time.time() - start_time < MAX_WAIT_TIME:
            r = requests.get(f"{CUCKOO_URL}/tasks/view/{task_id}")
            task_status = r.json()["task"]["status"]
            
            # 분석 완료 또는 실패 상태 확인
            if task_status == "reported":
                print("Cuckoo 분석 완료.")
                break
            
            if task_status in ["failed", "exception"]:
                raise Exception(f"Cuckoo 분석 실패: {task_status}")
            
            # 상태 변경 시에만 대시보드 업데이트 (로그 중복 방지)
            if task_status != last_status:
                current_status = "analyzing" if task_status in ["pending", "running"] else task_status
                upload_to_dashboard(file_key, 0, current_status, task_id, yara_matches=local_yara_matches)
                last_status = task_status

            time.sleep(5)
        else:
            # 타임아웃 발생 시
            raise Exception(f"Cuckoo 분석 타임아웃 (Task ID: {task_id})")

        # 4. 결과 리포트 가져오기
        report_json = requests.get(f"{CUCKOO_URL}/tasks/report/{task_id}").json()
        
        score = report_json.get("info", {}).get("score", 0)
        signatures = report_json.get("signatures", [])
        status = "CRITICAL" if score >= 7 else "WARNING" if score >= 4 else "CLEAN"
        
        # 5. Cuckoo YARA 결과 추출
        cuckoo_yara_matches = extract_cuckoo_yara(report_json)
        final_yara_matches = local_yara_matches + cuckoo_yara_matches
        
        print(f"분석 끝! 점수: {score}")
        print(f"최종 YARA 정보 (로컬 {len(local_yara_matches)} + Cuckoo {len(cuckoo_yara_matches)}): 총 {len(final_yara_matches)}건")
        
        report_url = upload_report_to_s3(task_id, file_key)
        
        # 6. AI 요약
        print(f"Gemini 요약 중...")
        ai_summary = get_ai_summary(signatures, score)
        
        # 7. 최종 결과 전송
        send_discord(file_key, score, task_id, report_url, ai_summary, final_yara_matches)
        upload_to_dashboard(file_key, score, status, task_id, report_url, ai_summary, final_yara_matches)

    except Exception as e:
        print(f"에러 발생: {e}")
        error_msg = f"분석 중 오류 발생: {str(e)}"
        send_discord(file_key, score, task_id if task_id else "N/A", None, error_msg, local_yara_matches)
        upload_to_dashboard(file_key, score, "ERROR", task_id if task_id else 0, ai_summary=error_msg)

def main():
    if not os.path.exists(DOWNLOAD_PATH): os.makedirs(DOWNLOAD_PATH)
    print(f"AI+Cuckoo 통합 감시 시작 (Local & Remote YARA Merge Mode)")
    processed = set()
    try:
        objs = s3.list_objects_v2(Bucket=S3_QUARANTINE)
        if 'Contents' in objs:
            for o in objs['Contents']: processed.add(o['Key'])
            print(f"기존 파일 {len(processed)}개 무시")
    except: pass

    while True:
        try:
            res = s3.list_objects_v2(Bucket=S3_QUARANTINE)
            if 'Contents' in res:
                sorted_files = sorted(res['Contents'], key=lambda x: x['LastModified'])
                for obj in sorted_files:
                    if obj['Key'] not in processed:
                        print(f"\n 발견: {obj['Key']}")
                        process_file(obj['Key'])
                        processed.add(obj['Key'])
            time.sleep(3)
        except Exception as e: time.sleep(3)

if __name__ == "__main__":
    main()

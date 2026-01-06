# 🛡️ Falco Security Rule Validator & Auto Recorder

**Falco 보안 규칙 검증을 위한 자동화 공격 및 증적 레코딩 도구**

이 프로젝트는 **DVWA(Damn Vulnerable Web App)** 환경을 대상으로 다양한 사이버 공격 시나리오(Command Injection, File Upload, Reverse Shell 등)를 자동으로 수행하고, 그 과정을 **영상으로 녹화**하여 Falco 탐지 로그와 비교 분석할 수 있도록 돕는 유닛 테스트 프레임워크입니다.

---

## ✨ 주요 기능 (Key Features)

*   **🎬 자동 화면 녹화**: 테스트의 모든 과정을 고화질(1080p), 다크 모드 브라우저로 녹화합니다. (증적 자료용)
*   **🚀 20+ 공격 시나리오**: Falco 룰셋 검증을 위한 Command Injection, Reverse Shell, 시스템 정찰 등 다양한 공격을 자동으로 수행합니다.
*   **🦠 악성 샘플 업로드**: `sample/` 폴더 내의 실제/가상 악성 파일을 랜덤으로 선택하여 업로드 테스트를 진행합니다.
*   **🏗️ Clean Architecture**: SOLID 원칙과 Clean Architecture 설계를 적용하여 유지보수가 용이합니다.
*   **⚡ 간편한 실행**: 쉘 스크립트 하나로 가상환경 생성부터 라이브러리 설치, 실행까지 한 번에 완료됩니다.

---

## 🛠️ 사전 요구 사항 (Prerequisites)

이 도구를 실행하기 위해 다음 환경이 필요합니다.

*   **OS**: macOS (권장) 또는 Linux
*   **Python**: 3.8 이상
*   **Browser**: Google Chrome (최신 버전)

---

## 🚀 시작하기 (Quick Start)

복잡한 설치 과정 없이, 아래 명령어 한 줄이면 준비 끝입니다!

```bash
# 1. 실행 권한 부여
chmod +x run_demo.sh

# 2. 데모 실행 (자동 설치 및 실행)
./run_demo.sh
```

> **참고**: `run_demo.sh` 스크립트는 `venv` 가상환경이 없으면 자동으로 생성하고, 필요한 라이브러리(`selenium`, `opencv` 등)를 설치한 후 프로그램을 실행합니다.

---

## 📖 사용 가이드 (User Guide)

프로그램을 실행하면 다음과 같은 절차로 테스트가 진행됩니다.

### 1. 설정 입력
터미널에서 테스트 대상 정보를 입력합니다. (엔터를 누르면 기본값이 적용됩니다.)
*   `DVWA URL`: 테스트할 대상 서버 주소 (예: `http://54.160.7.208:31100`)
*   `Username` / `Password`: DVWA 로그인 계정
*   `Security Level`: 보안 등급 (보통 `low` 사용)

### 2. 화면 배치 (5초 대기)
브라우저가 열리고 로그인 페이지에 접속하면, **5초간 대기 시간**이 주어집니다.
이때 **브라우저 창을 왼쪽**에, **터미널이나 디스코드(Slack) 알림창을 오른쪽**에 배치하여 녹화 구도를 잡으세요.

![Screen Layout Example](sample.png)
*(위 이미지와 같이 화면을 구성하면 공격 실행과 알림 발생을 한눈에 볼 수 있습니다.)*

### 3. 자동 테스트 진행
로그인이 완료되면 자동으로 공격 시나리오가 순차적으로 실행됩니다.
*   **Section 1**: DVWA Artifact Rules (웹쉘 생성, 권한 변경 등)
*   **Section 2**: Runtime Execution Rules (시스템 정찰, 리버스 쉘 등)
*   **Section 3**: Malware Upload (랜덤 샘플 파일 업로드)

### 4. 완료 및 결과
모든 테스트가 끝나면 **브라우저는 닫히지 않고 유지**됩니다.
생성된 녹화 영상(`falco_demo_YYYYMMDD_HHMMSS.mp4`)을 확인하세요.

---

## 📂 프로젝트 구조 (Project Structure)

```text
.
├── falco_demo_recorder.py   # [핵심] 🚀 메인 실행 코드 (테스트 로직 + 녹화)
├── run_demo.sh              # [실행] ⚡ 자동 실행 스크립트 (가상환경 관리)
├── requirements.txt         # [설정] 필수 파이썬 라이브러리 목록
├── generate_samples.py      # [도구] (옵션) 테스트용 더미 샘플 생성기
├── sample/                  # [데이터] 공격 테스트에 사용될 악성 샘플 폴더
├── install_demo_recorder.sh # [설치] (참고용) 수동 설치 스크립트
└── README.md                # [문서] 사용 설명서
```

---

## ⚠️ 주의 사항 (Disclaimer)

*   **악성 샘플 주의**: `sample/` 폴더가 포함된 경우, 실제 악성코드가 (확장자만 변경되어) 포함되어 있을 수 있습니다. **절대 로컬 PC에서 임의로 실행하지 마세요.**
*   **허가된 환경에서만 사용**: 이 도구는 실제 공격을 수행합니다. 본인이 소유하거나 사전에 허가받은 테스트 환경(DVWA 등)에서만 사용해야 합니다. 악의적인 목적으로 사용 시 법적 책임은 사용자에게 있습니다.

---
**Developed for Falco Security Rule Validation Unit Testing.**

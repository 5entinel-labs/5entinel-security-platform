# 5ENTINEL: Cloud-Native SOC Platform
> **AWS EKS 환경을 위한 실시간 보안 관제 및 자동 대응(SOAR) 플랫폼** > **KT Cloud TECH UP 사이버 보안 과정 1기 프로젝트 최종 결과물**

![Dashboard Preview](./dashboard/dashboard_preview.png)

<br/>

## 1. 프로젝트 개요 (Project Overview)
본 프로젝트는 **클라우드 네이티브(AWS EKS)** 환경에서 발생하는 보안 위협을 실시간으로 탐지하고 대응하기 위해 구축된 **Full-Stack 보안 관제 시스템**임.
<br>

**Falco**를 이용해 런타임 위협을 탐지하고, **YARA/Cuckoo**를 통해 하이브리드 멀웨어 분석을 수행하며, **Gemini AI**가 분석 결과를 요약하여 보안 담당자의 의사결정을 도움. 또한 **AWS Step Functions**를 활용해 탐지된 위협에 대한 자동 격리 및 차단 조치를 수행함.

* **개발 기간**: 2025.12 ~ 2026.01
* **핵심 목표**: 런타임 위협 탐지부터 분석, 대응까지의 **전 과정 자동화 및 시각화**

<br/>

## 2. 기술 스택 (Tech Stack)

| Category | Technology |
| --- | --- |
| **Compute & Container** | ![AWS EKS](https://img.shields.io/badge/AWS_EKS-FF9900?style=flat-square&logo=amazoncks&logoColor=white) ![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white) ![Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=flat-square&logo=awslambda&logoColor=white) |
| **Security & Monitor** | ![Falco](https://img.shields.io/badge/Falco-00AEC7?style=flat-square&logo=falco&logoColor=white) ![YARA](https://img.shields.io/badge/YARA-CC0000?style=flat-square) ![Cuckoo Sandbox](https://img.shields.io/badge/Cuckoo_Sandbox-008000?style=flat-square) |
| **Orchestration** | ![AWS Step Functions](https://img.shields.io/badge/Step_Functions-FF4F8B?style=flat-square&logo=amazonaws&logoColor=white) ![CloudWatch](https://img.shields.io/badge/CloudWatch-FF4F8B?style=flat-square&logo=amazonaws&logoColor=white) |
| **AI Intelligence** | ![Google Gemini](https://img.shields.io/badge/Gemini_AI-8E75B2?style=flat-square&logo=google&logoColor=white) |
| **Frontend** | ![React](https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black) ![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white) |

<br/>

## 3. 핵심 기능 (Key Features)

### 1) 실시간 위협 탐지 (Runtime Detection)
**Cloud-Native 런타임 보안 도구인 Falco**를 EKS Daemonset으로 배포하여 시스템 콜 레벨의 위협을 실시간 감지함.

*   **Threat Radar**: 위협 점수(Threat Score)를 기반으로 파일 및 런타임 위협을 레이더 화면에 실시간 시각화함.
*   **Emergency Mode**: 활성 사고(Falco 탐지) 발생 시 대시보드 전체 UI가 즉시 붉은색 점멸 긴급 모드로 전환되어 분석가의 인지를 도움.
*   **Pipeline Tracking**: 탐지부터 분석, 격리, 보고까지 이어지는 전체 보안 파이프라인의 진행 상태를 실시간 트래킹함.

<br>

### 2) 하이브리드 자동 분석 (Automated Analysis)
탐지된 의심 파일은 **분석 브릿지(Bridge Engine)**를 통해 정적/동적 분석이 수행됨.

| 분석 엔진 | 역할 및 기능 |
| :--- | :--- |
| **YARA (Static)** | • **Signature Matching**: 커스텀 룰셋을 기반으로 알려진 악성코드 패턴 및 문자열 신속 탐지<br>• **Local Scan**: 파일 내부의 API 호출 패턴 및 의심스러운 헤더 정보 추출 |
| **Cuckoo (Dynamic)** | • **Behavior Monitoring**: 격리된 샌드박스 환경에서 파일 실행<br>• **Trace Analysis**: 실제 발생하는 네트워크 연결, 파일 생성, 레지스트리 조작 행위 추적 |
| **Gemini AI** | • **Intel Summary**: 복잡한 YARA/Cuckoo 로그를 분석하여 **"3줄 요약"** 리포트 생성 (식별-위험-대응) |

### 3) 자동 대응 및 시각화 (SOAR & Dashboard)
* **AWS Step Functions**: 탐지된 Pod를 즉시 격리(`Labeling`)하거나 강제 종료(`Force Delete`)하는 워크플로우 자동 실행함
* **Dashboard Visualization**:
    * **Threat Radar**: 위협 점수에 따른 실시간 레이더 차트 시각화
    * **Emergency Mode**: 활성 위협 감지 시 붉은색 테마 전환으로 긴급 상황 전파함


### 4) 검증된 공격 시나리오 (Validated Attack Scenarios)

본 시스템은 실제 공격 기법을 시뮬레이션하여 방어 유효성을 검증함.

#### 1. Reverse Shell & Evasion
*   공격자가 웹 취약점을 통해 내부 침투 후 C2 서버로의 역접속을 시도함.
*   단순한 연결뿐만 아니라 우회 기법(Evasion)을 시도했으나, Falco 커스텀 룰을 통해 프로세스 트리와 네트워크 소켓 생성을 상관 분석하여 탐지함.

#### 2. DVWA Web Exploitation
*   DVWA를 타겟으로 자동화된 봇 공격 및 웹쉘 업로드 공격을 수행함.
*   웹 서버 프로세스가 쉘을 스폰하거나 비정상적인 경로에 파일을 쓰는 행위를 행위 기반으로 탐지함.

#### 3. Container Privilege Escalation
*   침투한 컨테이너 내부에서 권한 상승을 시도함.
*   탐지 즉시 SOAR가 트리거되어 해당 Pod를 네트워크 격리하거나 강제 종료함.


<br/>

## 4. 시스템 아키텍처 (Architecture)

<img width="1803" height="722" alt="Image" src="https://github.com/user-attachments/assets/0e5747eb-35ba-446b-9a3c-9d6fdc4ca924" />

1.  **Detection**: EKS 내부의 **Falco**가 시스템 콜을 감지하여 Fluent-Bit를 통해 로그 전송함
2.  **Collection**: CloudWatch Logs로 수집된 로그가 Lambda 트리거함
3.  **Automation**: **AWS Step Functions**가 대응 로직 실행 및 상태 갱신함 (`status.json`)
4.  **Analysis**: 의심 파일은 S3 격리 버킷으로 전송되어 **Cuckoo/YARA** 분석 수행함 (`latest.json`)
5.  **Visualization**: 대시보드는 S3의 데이터를 폴링하여 실시간 현황 표시함

<br/>

## 5. 프로젝트 구조 (Project Structure)

```code
5entinel-security-platform/
├── AWS_SOAR/            # AWS Step Function 기반 자동 대응 시나리오
├── dashboard/           # React 기반 통합 관제 프론트엔드 (S3 호스팅)
├── cuckoo/              # 분석 브릿지 엔진 (bridge.py - YARA/AI 통합)
├── falco/               # Falco 커스텀 룰(Rules) 및 Helm 설정
├── yara/                # YARA 룰 및 악성코드 탐지 시그니처
└── unit_test/           # 주요 기능 검증을 위한 테스트 코드
```


<br/>


## 6. 팀원 소개 (Team)

| 이름 | 역할 (Role) | 주요 기여 및 담당 파트 (Key Contributions) |
| :---: | :---: | :--- |
| **이영주** | **Team Leader** | • AWS EKS, Step Function/Lambda 등 공격 환경 및 자동대응 파이프라인 구축<br>• Falco 런타임 보안 설정<br>• 최종 Report Discord 출력 |
| **신유주** | **Member** | • Cuckoo Sandbox 구축 및 Gemini AI 분석 요약 자동화 연동<br>• 대시보드 UI/UX 설계 및 구현<br>• 분석 브릿지 개발 및 S3 기반 데이터 파이프라인 구축 |
| **이재일** | **Member** | • Falco 런타임 보안 설정 및 아키텍처 설계<br>• 리버스 쉘, 권한 상승 등 핵심 공격 시나리오 설계 및 검증 |
| **이영광** | **Member** | • QA 수행 및 Unit Test 수행 |
| **홍정수** | **Member** | • 오픈소스 YARA 룰 최적화 및 탐지 자동화 구현<br>• PHP 리버스 셸 및 PowerShell 스크립트 난독화 탐지 룰 개발 |

<br>

---
MIT License © 2026 5ENTINEL Team

# Falco Ruleset v0.3 (Project Exec + DVWA Artifact)

> 컨테이너/Kubernetes 환경에서 “컨테이너 내부 실행(Exec)”과 DVWA 업로드 기반 공격 징후를 탐지하기 위한 Falco 규칙 모음.

---

## ✨ 목표

- DVWA 업로드 디렉터리에서 생성/수정/실행되는 파일을 **아티팩트(artifact)** 이벤트로 기록
- 로그에 `artifact_path` 등을 포함해 후속 수집 파이프라인(S3/Collector 등)으로 넘기기 쉽게 구성
- 컨테이너 내부 실행(Exec) 행위를 카테고리(PRJ_EXEC_*)로 분류해 관제/감사에 활용

---

## 🧭 구성 개요

- **Scoping / helper macros**
  - 탐지 범위를 깔끔하게 제한하고, 규칙 조건을 재사용하기 위한 매크로/리스트들
- **DVWA ARTIFACT RULES (NEW)**
  - DVWA 네임스페이스에서 업로드/웹셸/다운로드/네트워크 연결 등 고신호 이벤트 탐지
- **PRJ EXEC RULES (v0.1 kept)**
  - 일반 컨테이너에서 실행되는 커맨드를 행위 기반으로 분류해 탐지/감사

---

## 🧩 스코프와 헬퍼

### `prj_scope`
- 프로젝트 범위용 스코프
- 기본/운영 네임스페이스(예: kube-system 등)는 제외하도록 설계

### `prj_exec_allowlist`
- 예외(화이트리스트) 용도 자리
- 현재는 비어 있는 상태(실질적으로 allowlist 비활성)로, 운영 중 예외를 추가하는 방식 권장

### DVWA 관련 매크로/리스트
- `dvwa_scope`: DVWA 네임스페이스의 컨테이너만 대상
- `dvwa_upload_dir`: DVWA 업로드 디렉터리 경로 범위 정의
- `dvwa_suspicious_ext`: 웹셸/스크립트/바이너리로 악용될 수 있는 확장자 목록
- `dvwa_archive_ext`: zip/tar/gz 등 아카이브 확장자 목록
- `dvwa_webserver_procs`: 웹서버/웹 런타임 프로세스 목록(apache/nginx/php 계열)

---

## 🧨 DVWA 아티팩트 규칙

> DVWA 업로드 기능을 악용한 웹셸 업로드, 페이로드 드롭/실행, C2(리버스쉘) 징후를 “아티팩트 이벤트”로 남기는 데 초점.

- **DVWA Webserver Outbound Connect (exit) attacker ip/port**
  - 웹서버 계열 프로세스의 외부 `connect`를 고신호로 탐지
  - 공격자 IP/Port를 로그에 포함(차단/자동화 연계 목적)

- **DVWA DEBUG any connect (show proc/ip/port)**
  - 디버깅용 규칙
  - 어떤 프로세스가 어떤 IP/Port로 연결했는지 확인할 때 사용

- **DVWA Upload Dir Suspicious Ext Written**
  - 업로드 디렉터리에 의심 확장자 파일이 “쓰기(open_write)”로 생성/수정되면 탐지
  - `artifact_path`로 파일 경로를 남겨 수집/격리 등 후속 처리에 활용

- **DVWA Upload Dir Archive Written**
  - 업로드 디렉터리에 아카이브 파일이 쓰이면 탐지
  - 압축 파일 기반 페이로드 전달/전개 가능성을 고려

- **DVWA Upload Dir File Write**
  - 업로드 디렉터리 하위 “모든 쓰기”를 넓게 기록(저신호/베이스라인 성격)

- **DVWA Upload Dir Chmod**
  - 업로드 디렉터리 내부 파일에 chmod 계열 이벤트가 발생하면 탐지
  - 실행 권한 부여 같은 행위 추적에 유용

- **DVWA Execute From Upload Dir**
  - 업로드 디렉터리 경로를 참조하는 실행(execve/execveat)을 강하게 탐지
  - 웹셸/드롭퍼 실행의 직접 신호로 활용

- **DVWA Webserver Spawns Shell**
  - 웹서버/웹런타임이 셸(sh/bash 등)을 spawn하면 CRITICAL로 탐지
  - 전형적인 웹셸/RCE 지표

- **DVWA Download Tool Writes To Upload Dir**
  - wget/curl 실행 커맨드가 업로드 디렉터리를 참조하면 탐지
  - “웹 경로로 페이로드를 받아오는 행위”를 가정

- **DVWA upload dir file move**
  - rename 계열 이벤트로 업로드 디렉터리로 파일이 이동되는 패턴을 탐지
  - tmp → uploads 같은 스테이징 흐름을 포착

---

## 🧪 PRJ Exec 규칙 (컨테이너 내부 실행 분류)

> DVWA에 한정하지 않고, `prj_scope` 범위의 컨테이너에서 프로세스 실행을 행위 기반으로 분류해 탐지/감사.

- **PRJ Exec Shell Interactive**
  - TTY가 붙은 인터랙티브 셸 실행 탐지(예: kubectl exec -it)

- **PRJ Exec Shell (Audit)**
  - 셸 실행 자체를 기본 감사 관점에서 기록

- **PRJ Exec Recon**
  - 정찰/열거 성격 커맨드(id/uname/ps/curl/wget 등) 실행 탐지

- **PRJ Exec Credential Search**
  - AWS/K8s/SSH 키 등 자격증명 탐색 패턴이 포함된 커맨드 탐지

- **PRJ Exec Fetch And Run**
  - 다운로드 후 실행(curl|sh, wget 후 bash -c 등) 패턴 탐지

- **PRJ Exec From Tmp Paths**
  - /tmp, /dev/shm 등 임시 경로에서 실행되거나 커맨드에 해당 경로가 포함되는 경우 탐지

- **PRJ Exec Archive/Staging**
  - tar/zip/gzip 등 아카이빙 명령 실행을 스테이징 징후로 기록

---

## 🧾 로그 포맷 팁

- DVWA 아티팩트 규칙들은 `ARTIFACT_*` 접두어와 `artifact_path=...`를 출력에 포함해 “무슨 파일이 문제인지”를 후속 자동화가 쉽게 소비하도록 설계
- 네트워크 규칙은 공격자 IP/Port 추출을 출력에 넣어 SOAR 차단 연계를 염두에 둔 형태

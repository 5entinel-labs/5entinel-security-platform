# 5entinel Security SOAR (Step Functions + Lambda)

> Falco 이벤트를 입력으로 받아 **증거 수집(S3)**, **파일 격리(Quarantine)**, **관리자 승인**, **노드 격리(EC2/ASG)**, **리버스쉘 차단(NACL)** 까지 자동으로 이어지는 SOAR 파이프라인입니다.

---

## 🧱 전체 아키텍처 (한 줄 요약)

- 입력: `$.falco.log` 또는 `$.falco.raw_message.log` 형태의 Falco 이벤트
- 처리: AWS Step Functions 상태머신이 이벤트 유형에 따라 Lambda들을 분기 호출
- 출력: 인시던트 JSON을 S3에 저장하고 Discord로 리포트 전송

---

## 🧭 상태머신 흐름(중요 경로)

### 1) 이벤트 분류: `ClassifyEvent`
- DVWA 업로드/파일 아티팩트 계열(`DVWA_UPLOAD_MOVE`, `ARTIFACT_WRITE*`)이면 **파일 추출 → 파일 격리 → SOAR 판단**으로 흐릅니다.
- 실행/웹셸/리버스쉘 의심(`PRJ_EXEC_*`, `ARTIFACT_WEBSHELL`, `ARTIFACT_EXEC`, `ARTIFACT_Reverse_Shell_Suspected!`)이면 바로 **SOAR 판단 단계**로 들어갑니다.
- 그 외는 기본적으로 인시던트 JSON을 만들고 저장/알림으로 넘어갑니다.

### 2) DVWA 파일 증거 처리: `ExtractFileToS3` → `DelaySuspiciousFile`
- `ExtractFileToS3`는 `5entinel_file_extract`를 호출하여, Falco 로그에서 `artifact_path`(또는 move의 dst/src)를 파싱하고 Pod/Container로 `exec` 해서 파일을 읽은 뒤 S3에 업로드합니다.
- `DelaySuspiciousFile`는 `5entinel_file_delay`를 호출하여, 같은 입력을 정규화한 다음 업로드 디렉터리의 파일을 quarantine 디렉터리로 **이동+이름변경(mv)** 하는 방식으로 격리합니다.

### 3) 심각도 기반 SOAR: `CheckSeverityForSOAR`
- 리버스쉘 의심 로그면 `ParseReverseShellIoC`로 이동합니다.
- 웹셸 의심(`ARTIFACT_WEBSHELL`)이면 곧바로 노드 격리(`ExecuteSoarResponse`)로 이동합니다.
- `ARTIFACT_EXEC` 또는 `PRJ_EXEC_*` 계열이면 관리자 승인(`AskForApproval`)로 이동합니다.

### 4) 리버스쉘 대응: `ParseReverseShellIoC` → `AddNaclOutboundDenyRule`
- `5entinel_parse_reverse_shell_ioc`가 Falco 로그에서 `Attacker_IP`, `Attacker_Port`를 정규식으로 파싱해 구조화된 IoC를 만듭니다.
- `5entinel_nacl_egress_deny_add`가 해당 IP를 `/32`로 변환한 뒤, TCP 특정 포트에 대해 NACL egress **deny 룰을 생성(또는 이미 있으면 재사용)** 합니다.

### 5) 관리자 승인: `AskForApproval` → `CheckAdminDecision`
- `AskForApproval`는 `lambda:invoke.waitForTaskToken` 패턴으로 동작하며, Discord에 “Allow / Block” 링크를 보내고 응답을 기다립니다.
- 관리자가 `block`을 선택하면 격리 단계(`ExecuteSoarResponse`)로 진행하고, 그 외에는 인시던트 기록 단계로 진행합니다.

### 6) 노드 격리: `ExecuteSoarResponse`
- `5entinel_node_isolate`가 노드(hostname)로 EC2 인스턴스를 식별한 뒤, **EBS 스냅샷 생성 → ASG Standby(가능한 경우) → 인스턴스 Stop + 태깅** 순서로 격리합니다.

### 7) 인시던트 저장/리포트: `BuildIncidentS3Key` → `PutIncidentToS3` → `SendDiscordReport`
- 실행 시작 시간과 실행 이름으로 `incidents/{StartTime}/{ExecutionName}.json` 형태의 키를 만들고, 전체 상태 입력을 JSON 문자열로 저장합니다.
- 저장 후 `5entinel_siem_discord`로 리포트를 전송하고 종료합니다.

---

## 🔧 Lambda별 역할 요약

| Lambda | 역할 | 핵심 입력 | 핵심 출력/효과 |
|---|---|---|---|
| `5entinel_file_extract` | K8s Pod에서 파일을 읽어 S3로 업로드 | Falco 이벤트(로그 포함) | `{uploaded, bucket, key, sha256, normalized}` |
| `5entinel_file_delay` | 의심 파일 quarantine 디렉터리로 이동+리네임 | Falco 이벤트 또는 file_extract 결과 | `{delayed, dst_path, new_name, sha256, normalized}` |
| `5entinel_parse_reverse_shell_ioc` | `Attacker_IP/Port` 파싱 | `$.falco` | `{attacker_ip, attacker_port}` |
| `5entinel_nacl_egress_deny_add` | NACL egress deny 룰 추가(IPv4 /32) | `{attacker_ip, attacker_port, falco}` | `{status, rule_number, cidr, port}` |
| `5entinel_ask_approval` | Discord로 승인 요청(토큰 링크) + StepFn 대기 | `{token, falco}` | “대기” 상태(승인은 callback에서 처리) |
| `5entinel_soar_callback` | 승인 링크 클릭 결과로 StepFn task success 호출 | API Gateway QueryString (`action`, `taskToken`) | `send_task_success`로 워크플로우 재개 |
| `5entinel_node_isolate` | EC2 노드 격리(스냅샷/ASG/Stop) | `{node_name}` 또는 falco에서 host | 인스턴스 중지 및 포렌식 스냅샷 |

---

## 🧪 입력/데이터 형태(운영 팁)

- Falco 로그는 `$.falco.log` 또는 `$.falco.raw_message.log` 둘 중 하나로 들어와도 분기/파싱되도록 구성되어 있습니다.
- 파일 계열 이벤트는 로그에서 `artifact_path=...` 또는 move 이벤트의 `src=...`, `dst=...`를 파싱해 K8s 대상(ns/pod/container)과 함께 처리합니다.
- 관리자 승인 플로우는 **Step Functions task token**을 URL에 실어 보내고(`allow/block`), callback이 그 토큰으로 Step Functions에 결과를 전달하는 방식입니다.

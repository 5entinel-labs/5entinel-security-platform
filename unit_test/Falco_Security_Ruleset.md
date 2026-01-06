# **Falco Security Ruleset: Project Exec v0.2.1 (Full Context)**

## **1\. 개요 및 목적 (Context & Objective)**

* **프로젝트 명**: Project Exec (v0.2.1)  
* **핵심 목표**:  
  1. 컨테이너 런타임 내 비정상 행위 분류 및 탐지 (v0.1 호환).  
  2. DVWA 환경의 아티팩트 추출 및 캡처 자동화 (S3/Collector 연동).  
  3. 실시간 침입 탐지 및 포렌식 증거(artifact\_path) 확보.

## **2\. 보안 분석 범위 (Scoping & Macros)**

* **전역 범위 (prj\_scope)**: 주요 시스템 네임스페이스를 제외한 일반 컨테이너 모니터링.  
* **DVWA 전용 범위 (dvwa\_scope)**: dvwa 네임스페이스 내부 활동 감시.  
* **민감 경로**: /var/www/html/hackable/uploads/ (공격자의 주 타겟).

## **3\. 탐지 로직 요약 (Detection Logic Summary)**

* **DVWA 특화**: 파일 쓰기, 위험 확장자(.php 등), 권한 변경(chmod), 업로드 경로 내 실행, 웹서버의 쉘 생성 탐지.  
* **일반 런타임**: 정찰(Recon), 자격증명 탈취 시도, 페이로드 다운로드 및 실행, 임시 경로(/tmp) 실행, 리버스 쉘 도구 탐지.

## **4\. 원본 규칙 소스 (Full Raw YAML Content)**

\# \=========================  
\# Project Exec Ruleset v0.2.1 test  
\# \=========================

\# \---- Scoping / helper macros \----  
\- macro: prj\_scope  
  condition: \>  
    (container and not k8s.ns.name in (kube-system, kube-public, kube-node-lease, falco, fluent-bit, external-dns))

\- macro: prj\_exec\_allowlist  
  condition: (never\_true)

\- macro: dvwa\_scope  
  condition: \>  
    container and k8s.ns.name=dvwa

\- macro: dvwa\_upload\_dir  
  condition: fd.name startswith /var/www/html/hackable/uploads/

\- list: dvwa\_suspicious\_ext  
  items: \[.php, .phtml, .php3, .php4, .php5, .phar, .sh, .bash, .py, .pl, .rb, .so\]

\- list: dvwa\_archive\_ext  
  items: \[.zip, .tar, .gz, .tgz\]

\- list: dvwa\_webserver\_procs  
  items: \[apache2, httpd, nginx, php-fpm, php, fpm-fcgi\]

\- list: prj\_shells  
  items: \[sh, bash, ash, dash, zsh\]

\- list: prj\_recon\_bins  
  items: \[id, whoami, uname, ps, top, env, printenv, ls, cat, find, grep, egrep, fgrep, ip, ifconfig, ss, netstat, route, ping, traceroute, nslookup, dig, curl, wget\]

\- list: prj\_cred\_search\_bins  
  items: \[cat, find, grep, egrep, fgrep, sed, awk, perl, python, python3\]

\- list: prj\_dropper\_bins  
  items: \[sh, bash, curl, wget, nc, ncat, socat, python, python3, perl, php, ruby, base64\]

\- list: prj\_archive\_bins  
  items: \[tar, gzip, gunzip, zip, unzip, xz, bzip2\]

\- list: prj\_remote\_exec\_bins  
  items: \[nc, ncat, socat, bash, sh, python, python3, perl, php, ruby\]

\# \---- DVWA ARTIFACT RULES \----  
\- rule: DVWA Upload Dir File Write  
  condition: \>  
    open\_write and dvwa\_scope and dvwa\_upload\_dir  
  output: \>  
    ARTIFACT\_WRITE reason=upload\_write artifact\_path=%fd.name proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: NOTICE

\- rule: DVWA Upload Dir Suspicious Ext Written  
  condition: \>  
    open\_write and dvwa\_scope and dvwa\_upload\_dir and ( fd.name endswith .php or fd.name endswith .phtml or fd.name endswith .php3 or fd.name endswith .php4 or fd.name endswith .php5 or fd.name endswith .phar or fd.name endswith .sh or fd.name endswith .bash or fd.name endswith .py or fd.name endswith .pl or fd.name endswith .rb or fd.name endswith .so )  
  output: \>  
    ARTIFACT\_WRITE\_SUSP\_EXT reason=upload\_write\_suspicious\_ext artifact\_path=%fd.name proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: DVWA Upload Dir Archive Written  
  condition: \>  
    open\_write and dvwa\_scope and dvwa\_upload\_dir and ( fd.name endswith .zip or fd.name endswith .tar or fd.name endswith .gz or fd.name endswith .tgz )  
  output: \>  
    ARTIFACT\_WRITE\_ARCHIVE reason=upload\_write\_archive artifact\_path=%fd.name proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: NOTICE

\- rule: DVWA Upload Dir Chmod  
  condition: \>  
    evt.type in (chmod, fchmod, fchmodat) and dvwa\_scope and dvwa\_upload\_dir  
  output: \>  
    ARTIFACT\_CHMOD reason=chmod artifact\_path=%fd.name proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: NOTICE

\- rule: DVWA Execute From Upload Dir  
  condition: \>  
    evt.type in (execve, execveat) and dvwa\_scope and ( proc.exepath startswith /var/www/html/hackable/uploads/ or proc.cmdline contains "/var/www/html/hackable/uploads/" )  
  output: \>  
    ARTIFACT\_EXEC reason=exec\_from\_upload\_dir exepath=%proc.exepath cmdline=%proc.cmdline container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname user=%user.name  
  priority: WARNING

\- rule: DVWA Webserver Spawns Shell  
  condition: \>  
    evt.type in (execve, execveat) and dvwa\_scope and proc.name in (sh, bash, dash, ash) and proc.pname in (dvwa\_webserver\_procs)  
  output: \>  
    ARTIFACT\_WEBSHELL reason=webserver\_spawns\_shell parent=%proc.pname proc=%proc.name cmdline=%proc.cmdline container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname user=%user.name  
  priority: WARNING

\- rule: DVWA Download Tool Writes To Upload Dir  
  condition: \>  
    evt.type in (execve, execveat) and dvwa\_scope and proc.name in (wget, curl) and proc.cmdline contains "/var/www/html/hackable/uploads/"  
  output: \>  
    ARTIFACT\_FETCH\_TO\_UPLOAD reason=download\_to\_upload\_dir cmdline=%proc.cmdline container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname user=%user.name  
  priority: WARNING

\- rule: DVWA upload dir file move  
  condition: \>  
    (evt.type in (rename, renameat, renameat2)) and k8s.ns.name \= "dvwa" and fs.path.target startswith "/var/www/html/hackable/uploads/"  
  output: \>  
    DVWA\_UPLOAD\_MOVE src=%fs.path.source dst=%fs.path.target proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name  
  priority: NOTICE

\# \---- PRJ EXEC RULES (General) \----  
\- rule: PRJ Exec Shell (Audit)  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and proc.name in (prj\_shells) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_AUDIT proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname tty=%proc.tty  
  priority: NOTICE

\- rule: PRJ Exec Shell Interactive  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and proc.name in (prj\_shells) and proc.tty \!= 0 and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_INTERACTIVE proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname tty=%proc.tty  
  priority: WARNING

\- rule: PRJ Exec Recon  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and proc.name in (prj\_recon\_bins) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_RECON proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: PRJ Exec Credential Search  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and proc.name in (prj\_cred\_search\_bins) and ( proc.cmdline contains ".aws/credentials" or proc.cmdline contains "AWS\_ACCESS\_KEY\_ID" or proc.cmdline contains "AWS\_SECRET\_ACCESS\_KEY" or proc.cmdline contains "BEGIN OPENSSH PRIVATE KEY" or proc.cmdline contains "BEGIN RSA PRIVATE KEY" or proc.cmdline contains "/var/run/secrets/kubernetes.io/serviceaccount/token" or proc.cmdline contains "kubeconfig" or proc.cmdline contains "id\_rsa" or proc.cmdline contains "id\_ed25519" ) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_CRED proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: PRJ Exec Fetch And Run  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and ( (proc.name in (curl, wget) and (proc.cmdline contains "http://" or proc.cmdline contains "https://")) or (proc.name in (prj\_shells) and ( proc.cmdline contains "curl " or proc.cmdline contains "wget " or proc.cmdline contains "| sh" or proc.cmdline contains "|bash" or proc.cmdline contains "bash \-c" or proc.cmdline contains "sh \-c" )) ) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_FETCHRUN proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: PRJ Exec From Tmp Paths  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and ( proc.exepath startswith "/dev/shm/" or proc.exepath startswith "/tmp/" or proc.cmdline contains "/dev/shm/" or proc.cmdline contains "/tmp/" ) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_TMP proc=%proc.name exepath=%proc.exepath cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: PRJ Exec Reverse Shell Tooling  
  condition: \>  
    evt.type in (execve, execveat, connect) and prj\_scope and ( (proc.name in (nc, ncat) and (proc.cmdline contains " \-e" or proc.cmdline contains " \-c" or proc.cmdline contains "--exec" or proc.cmdline contains "--sh-exec")) or (proc.name in (prj\_shells) and (proc.cmdline contains "bash \-i" or proc.cmdline contains "/dev/tcp/")) or (proc.name in (python, python3, perl, php, ruby) and (proc.cmdline contains "socket" or proc.cmdline contains "connect")) or (evt.type=connect and proc.pname in (nc, ncat, socat, python, python3, perl, php, ruby, bash, sh)) ) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_REVSH proc=%proc.name cmdline=%proc.cmdline attacker\_ip=%fd.sip connection=%fd.name user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: WARNING

\- rule: PRJ Exec Archive/Staging  
  condition: \>  
    evt.type in (execve, execveat) and prj\_scope and proc.name in (prj\_archive\_bins) and not prj\_exec\_allowlist  
  output: \>  
    PRJ\_EXEC\_ARCHIVE proc=%proc.name cmdline=%proc.cmdline user=%user.name container=%container.name container\_id=%container.id pod=%k8s.pod.name ns=%k8s.ns.name node=%evt.hostname  
  priority: NOTICE

## **5\. 안티그래비티 활용 가이드 (Instruction for AI)**

1. 이 문서의 '4번 원본 소스'를 기반으로 사용자의 보안 이벤트를 분석할 것.  
2. ARTIFACT\_ 프리픽스는 즉각적인 포렌식 대응이 필요한 '고신호(High Signal)' 이벤트임.  
3. PRJ\_EXEC\_ 프리픽스는 일반적인 침해 사고 단계(Recon, Credential Access, Exfiltration)를 의미함.
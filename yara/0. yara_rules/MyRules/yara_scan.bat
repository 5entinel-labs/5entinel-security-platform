@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

:: 1. 경로 설정 (사용자님이 주신 정확한 통합 룰 경로 적용)
set "YARA_DIR=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara-4.5.5-2368-win64"
set "RULES_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\TOTAL_RULES.yar"
set "TARGET_FILE=C:\Users\user\Downloads\3. web_payload_test2.php"
set "REPORT_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\ADVANCED_THREAT_REPORT.txt"

echo [시스템] 통합 룰 파일을 이용한 정밀 분석을 시작합니다...

:: 해시 및 파일 정보 추출
set "sha256=N/A"
for /f "skip=1 delims=" %%# in ('certutil -hashfile "%TARGET_FILE%" SHA256 2^>nul') do (if "!sha256!"=="N/A" (set "res=%%#" & set "sha256=!res: =!"))
set "short_sha=!sha256:~0,12!"
for %%A in ("%TARGET_FILE%") do set "file_size=%%~zA" & set "file_date=%%~tA"

:: 2. 리포트 초기화
echo ====================================================================== > "%REPORT_FILE%"
echo           프리미엄 사이버 위협 정밀 분석 보고서 (v2.5)               >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"
echo [섹션 1. 대상 식별 정보] >> "%REPORT_FILE%"
echo  - 파일 경로     : %TARGET_FILE% >> "%REPORT_FILE%"
echo  - 해시 (SHA256) : !sha256! >> "%REPORT_FILE%"
echo  - 파일 생성일   : %file_date% >> "%REPORT_FILE%"
echo  - 분석 일시     : %date% %time% >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 2. YARA 엔진 상세 탐지 내역] >> "%REPORT_FILE%"
echo  [룰 이름]          [매칭 위치]     [탐지 패턴] >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

:: 3. YARA 실행 (통합 룰 파일 직접 지정)
pushd "%YARA_DIR%"
set /a "found_count=0"

:: -m(메타), -s(스트링), -g(태그) 옵션으로 상세 매칭 강제 출력
yara64.exe -m -s -g "%RULES_FILE%" "%TARGET_FILE%" 2>nul | findstr /v "warning" > "%temp%\yara_final.txt"

:: 매칭 결과 한 줄씩 리포트에 기록
for /f "usebackq tokens=*" %%L in ("%temp%\yara_final.txt") do (
    echo  %%L >> "%REPORT_FILE%"
    set /a "found_count+=1"
)
popd

:: 4. 위험 점수 및 등급 산정
set /a "risk_score=10"
if !found_count! gtr 0 (
    set /a "risk_score=50 + (found_count * 5)"
    if !risk_score! gtr 100 set "risk_score=100"
)

echo. >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 3. 위험도 평가 및 분석 결과] >> "%REPORT_FILE%"
echo  - 종합 위협 점수 : [!risk_score! / 100 점] >> "%REPORT_FILE%"

if !risk_score! geq 70 (
    echo  - 위협 등급      : 심각 (CRITICAL) >> "%REPORT_FILE%"
) else if !risk_score! geq 40 (
    echo  - 위협 등급      : 경고 (WARNING) >> "%REPORT_FILE%"
) else (
    echo  - 위협 등급      : 정상 (CLEAN) >> "%REPORT_FILE%"
)
echo  - 탐지 패턴 수   : !found_count!개 확인 >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 4. 사고 대응 가이드라인] >> "%REPORT_FILE%"
echo  1. 조치 사항 : 감염 의심 파일 격리 및 네트워크 통신 차단 권고 >> "%REPORT_FILE%"
echo  2. 외부 대조 : https://www.virustotal.com/gui/file/!sha256! >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo [분석 요약 테이블] >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
echo  파일명               ^| SHA256 (일부)   ^| 위협점수 ^| 상태       ^| 권고 조치 >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"

for %%F in ("%TARGET_FILE%") do set "fname=%%~nxF"
if !found_count! gtr 0 (set "stat=감염의심") else (set "stat=정상파일")
echo  !fname! ^| !short_sha! ^| !risk_score!/100      ^| !stat!   ^| 즉시 대응 필요 >> "%REPORT_FILE%"

echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"

del "%temp%\yara_final.txt" 2>nul
echo [완료] 상세 매칭 내역이 포함된 리포트가 생성되었습니다.
pause
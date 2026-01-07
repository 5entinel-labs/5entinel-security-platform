@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

:: 1. 경로 설정
set "YARA_DIR=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara-4.5.5-2368-win64"
set "RULES_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\TOTAL_RULES.yar"
set "TARGET_FILE=C:\Users\user\Downloads\3. web_payload_test2.php"
set "REPORT_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\ADVANCED_THREAT_REPORT.txt"

echo [시스템] 통합 룰 분석 및 리포트 생성을 시작합니다...

:: 해시 추출
set "sha256=N/A"
for /f "skip=1 delims=" %%# in ('certutil -hashfile "%TARGET_FILE%" SHA256 2^>nul') do (if "!sha256!"=="N/A" (set "res=%%#" & set "sha256=!res: =!"))
set "short_sha=!sha256:~0,12!"
for %%A in ("%TARGET_FILE%") do set "file_date=%%~tA"

:: 2. 리포트 헤더 작성
echo ====================================================================== > "%REPORT_FILE%"
echo           프리미엄 사이버 위협 정밀 분석 보고서 (v3.0)                >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"
echo [섹션 1. 대상 식별 정보] >> "%REPORT_FILE%"
echo  - 파일 경로     : %TARGET_FILE% >> "%REPORT_FILE%"
echo  - 해시 (SHA256) : !sha256! >> "%REPORT_FILE%"
echo  - 분석 일시     : %date% %time% >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 2. YARA 엔진 상세 탐지 내역] >> "%REPORT_FILE%"

:: 3. YARA 실행 및 파싱
pushd "%YARA_DIR%"
set /a "found_count=0"
yara64.exe -m -s -g "%RULES_FILE%" "%TARGET_FILE%" > "%temp%\yara_raw.txt" 2>&1

for /f "usebackq tokens=*" %%L in ("%temp%\yara_raw.txt") do (
    set "line=%%L"
    echo !line! | findstr /v "warning:" >nul
    if !errorlevel! == 0 (
        :: 패턴 라인 (0x로 시작) 처리
        echo !line! | findstr /r "^0x" >nul
        if !errorlevel! == 0 (
            for /f "tokens=1,3 delims=:$ " %%a in ("!line!") do (
                echo  [매칭 위치] : %%a >> "%REPORT_FILE%"
                echo  [탐지 패턴] : %%b >> "%REPORT_FILE%"
                echo  -------------------------------------- >> "%REPORT_FILE%"
            )
        ) else (
            :: 룰 이름 및 태그 라인 처리
            for /f "tokens=1,2" %%r in ("!line!") do (
                echo. >> "%REPORT_FILE%"
                echo  [룰 이름]   : %%r >> "%REPORT_FILE%"
                echo  [태그 정보] : %%s >> "%REPORT_FILE%"
                echo  -------------------------------------- >> "%REPORT_FILE%"
            )
        )
        set /a "found_count+=1"
    )
)
popd

:: 4. 위험 점수 산정 및 등급 출력
set /a "risk_score=0"
if !found_count! gtr 0 (
    set /a "risk_score=60 + (found_count * 2)"
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
echo  파일명                ^| SHA256 (일부)   ^| 위협점수 ^| 상태       ^| 권고 조치 >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
for %%F in ("%TARGET_FILE%") do set "fname=%%~nxF"
if !found_count! gtr 0 (set "stat=감염의심") else (set "stat=정상파일")
echo  !fname! ^| !short_sha! ^| !risk_score!/100      ^| !stat!   ^| 즉시 대응 필요 >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"

del "%temp%\yara_raw.txt" 2>nul
echo [완료] 분석 보고서가 생성되었습니다.
pause
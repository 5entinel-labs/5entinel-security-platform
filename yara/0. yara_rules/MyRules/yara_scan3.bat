@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

:: 1. 경로 설정
set "YARA_DIR=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara-4.5.5-2368-win64"
set "RULES_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\TOTAL_RULES.yar"
set "TARGET_FILE=C:\Users\user\Downloads\3. web_payload_test2.php"
set "REPORT_FILE=C:\Users\user\Desktop\20251010_파일이동\0. KT 클라우드 사이버 보안\심화 프로젝트\yara_rules\yara_rules\MyRules\ADVANCED_THREAT_REPORT.txt"

echo [시스템] 통합 룰 분석 및 정밀 리포트 생성을 시작합니다...

:: 해시 및 파일 정보 추출
set "sha256=N/A"
for /f "skip=1 delims=" %%# in ('certutil -hashfile "%TARGET_FILE%" SHA256 2^>nul') do (if "!sha256!"=="N/A" (set "res=%%#" & set "sha256=!res: =!"))
set "short_sha=!sha256:~0,12!"
for %%A in ("%TARGET_FILE%") do set "file_size=%%~zA" & set "file_date=%%~tA"

:: 2. 리포트 초기화 및 헤더 (안정성을 위해 개별 echo 사용)
echo ====================================================================== > "%REPORT_FILE%"
echo           프리미엄 사이버 위협 정밀 분석 보고서 (v3.8)                >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"
echo [섹션 1. 대상 식별 정보] >> "%REPORT_FILE%"
echo  - 파일 경로     : %TARGET_FILE% >> "%REPORT_FILE%"
echo  - 해시 (SHA256) : !sha256! >> "%REPORT_FILE%"
echo  - 파일 생성일   : %file_date% >> "%REPORT_FILE%"
echo  - 분석 일시     : %date% %time% >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 2. YARA 엔진 상세 탐지 내역] >> "%REPORT_FILE%"

:: 3. YARA 실행 및 스마트 파싱 (탐지 패턴 추출 보완)
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
            for /f "tokens=1,2* delims=:" %%a in ("!line!") do (
                echo    - [매칭 위치] : %%a >> "%REPORT_FILE%"
                echo    - [탐지 패턴] :%%c >> "%REPORT_FILE%"
                echo    -------------------------------------- >> "%REPORT_FILE%"
            )
        ) else (
            :: 룰 이름 라인 처리 (빈 태그 필터링)
            for /f "tokens=1,2" %%r in ("!line!") do (
                echo. >> "%REPORT_FILE%"
                echo ■ 탐지 규칙 : %%r >> "%REPORT_FILE%"
                set /a "found_count+=1"
            )
        )
    )
)
popd

:: 4. 위험 점수 및 단일 등급 산정 (중복 출력 방지)
set /a "risk_score=10"
if !found_count! gtr 0 (
    set /a "risk_score=60 + (!found_count! * 2)"
    if !risk_score! gtr 100 set "risk_score=100"
)

set "final_grade=정상 (CLEAN)"
if !risk_score! geq 70 (
    set "final_grade=심각 (CRITICAL)"
) else if !risk_score! geq 40 (
    set "final_grade=경고 (WARNING)"
)

:: 5. 분석 결과 출력
echo. >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 3. 위험도 평가 및 분석 결과] >> "%REPORT_FILE%"
echo  - 종합 위협 점수 : [!risk_score! / 100 점] >> "%REPORT_FILE%"
echo  - 위협 등급      : !final_grade! >> "%REPORT_FILE%"
echo  - 탐지 패턴 수   : !found_count!개 확인 >> "%REPORT_FILE%"
echo ---------------------------------------------------------------------- >> "%REPORT_FILE%"
echo [섹션 4. 사고 대응 가이드라인] >> "%REPORT_FILE%"
echo  1. 조치 사항 : 감염 의심 파일 격리 및 네트워크 통신 차단 권고 >> "%REPORT_FILE%"
echo  2. 외부 대조 : https://www.virustotal.com/gui/file/!sha256! >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

:: 6. 분석 요약 테이블 (특수문자 에러 해결을 위해 구조 변경)
echo [분석 요약 테이블] >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
for %%F in ("%TARGET_FILE%") do set "fname=%%~nxF"
if !found_count! gtr 0 (set "stat=감염의심") else (set "stat=정상파일")
echo  파일명    : !fname! >> "%REPORT_FILE%"
echo  해시(일부): !short_sha! >> "%REPORT_FILE%"
echo  위협점수  : !risk_score! / 100 >> "%REPORT_FILE%"
echo  최종상태  : !stat! >> "%REPORT_FILE%"
echo ----------------------------------------------------------------------------------------- >> "%REPORT_FILE%"
echo ====================================================================== >> "%REPORT_FILE%"

del "%temp%\yara_raw.txt" 2>nul
echo [완료] 끊김 없이 모든 정보가 포함된 리포트가 생성되었습니다.
pause
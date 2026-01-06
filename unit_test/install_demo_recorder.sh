#!/bin/bash
################################################################################
# Falco 데모 레코더 설치 스크립트
# 설명: 필요한 모든 패키지를 자동으로 설치합니다
################################################################################

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Falco 데모 레코더 설치 스크립트                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Python 버전 확인
echo -e "${YELLOW}[1/5]${NC} Python 버전 확인 중..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3가 설치되어 있지 않습니다."
    echo "  설치 방법: brew install python3"
    exit 1
fi

# pip 업그레이드
echo -e "\n${YELLOW}[2/5]${NC} pip 업그레이드 중..."
python3 -m pip install --upgrade pip --quiet
echo -e "${GREEN}✓${NC} pip 업그레이드 완료"

# Selenium 설치
echo -e "\n${YELLOW}[3/5]${NC} Selenium 설치 중..."
pip3 install selenium --quiet
echo -e "${GREEN}✓${NC} Selenium 설치 완료"

# 화면 녹화 라이브러리 설치
echo -e "\n${YELLOW}[4/5]${NC} 화면 녹화 라이브러리 설치 중..."
echo "  (opencv-python, pillow, numpy)"
pip3 install opencv-python pillow numpy --quiet
echo -e "${GREEN}✓${NC} 화면 녹화 라이브러리 설치 완료"

# ChromeDriver 설치
echo -e "\n${YELLOW}[5/5]${NC} ChromeDriver 확인 중..."
if command -v chromedriver &> /dev/null; then
    CHROMEDRIVER_VERSION=$(chromedriver --version)
    echo -e "${GREEN}✓${NC} $CHROMEDRIVER_VERSION"
else
    echo -e "${YELLOW}⚠${NC}  ChromeDriver가 설치되어 있지 않습니다."
    echo ""
    echo "ChromeDriver 설치 방법:"
    echo ""
    echo "  방법 1: Homebrew 사용 (권장)"
    echo "    brew install chromedriver"
    echo ""
    echo "  방법 2: 수동 설치"
    echo "    1. Chrome 버전 확인: chrome://version"
    echo "    2. https://chromedriver.chromium.org/downloads"
    echo "    3. 같은 버전의 chromedriver 다운로드"
    echo "    4. /usr/local/bin/에 복사"
    echo ""
    read -p "지금 Homebrew로 설치하시겠습니까? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v brew &> /dev/null; then
            brew install chromedriver
            echo -e "${GREEN}✓${NC} ChromeDriver 설치 완료"
        else
            echo -e "${RED}✗${NC} Homebrew가 설치되어 있지 않습니다."
            echo "  Homebrew 설치: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        fi
    fi
fi

# 설치 완료
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                   설치 완료!                              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "설치된 패키지:"
echo "  ✓ Python 3"
echo "  ✓ Selenium"
echo "  ✓ opencv-python"
echo "  ✓ pillow"
echo "  ✓ numpy"
if command -v chromedriver &> /dev/null; then
    echo "  ✓ ChromeDriver"
else
    echo "  ⚠ ChromeDriver (수동 설치 필요)"
fi

echo ""
echo "다음 단계:"
echo "  1. falco_demo_recorder.py 파일에서 DVWA_URL 설정"
echo "  2. python3 falco_demo_recorder.py 실행"
echo ""
echo "자세한 사용법: DEMO_RECORDER_GUIDE.md 참고"
echo ""

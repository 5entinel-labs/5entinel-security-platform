#!/bin/bash
################################################################################
# Falco 데모 레코더 실행 스크립트 (가상 환경용)
# 설명: 가상 환경을 활성화하고 데모 레코더를 실행합니다
################################################################################

echo "🚀 Falco 데모 레코더 시작..."
echo ""

# 가상 환경 확인 및 생성
if [ ! -d "venv" ]; then
    echo "⚙️  가상 환경이 없습니다. 새로 생성합니다..."
    python3 -m venv venv
    
    echo "✓ 가상 환경 활성화 중..."
    source venv/bin/activate
    
    echo "📦 필수 패키지 설치 중..."
    pip install -r requirements.txt
    
    echo "✅ 설치 완료!"
    echo ""
else
    echo "✓ 가상 환경 활성화 중..."
    source venv/bin/activate
fi

# Python 스크립트 실행
echo "✓ 데모 레코더 실행 중..."
echo ""
python falco_demo_recorder.py

# 가상 환경 비활성화
deactivate

echo ""
echo "✅ 완료!"

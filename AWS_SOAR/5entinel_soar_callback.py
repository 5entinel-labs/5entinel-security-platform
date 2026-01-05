import json
import boto3
import os

sfn = boto3.client('stepfunctions')

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))  # 디버깅용 로그
    
    # 1. API Gateway를 통해 들어온 파라미터 추출
    # (HTTP API와 REST API 방식이 약간 다를 수 있어 안전하게 get 사용)
    query_params = event.get('queryStringParameters', {})
    
    if not query_params:
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'text/plain; charset=utf-8'},
            'body': "Error: No parameters found."
        }

    action = query_params.get('action')
    task_token = query_params.get('taskToken')

    if not action or not task_token:
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'text/plain; charset=utf-8'},
            'body': "Error: Missing action or taskToken."
        }

    # 2. Step Functions 상태 업데이트
    try:
        if action == 'allow':
            message = "✅ 승인 처리되었습니다 (Access Allowed)"
            sfn.send_task_success(
                taskToken=task_token,
                # [수정] 키를 'action'으로, 값을 'allow'로 변경
                output=json.dumps({'action': 'allow', 'message': message})
            )
        elif action == 'block':
            message = "🛑 차단 처리되었습니다 (Access Denied)"
            sfn.send_task_success(
                taskToken=task_token,
                # [수정] 키를 'action'으로, 값을 'block'으로 변경
                output=json.dumps({'action': 'block', 'message': message})
            )
        else:
            message = "⚠️ 알 수 없는 요청입니다."
            
        # 3. 사용자(웹 브라우저)에게 보여줄 응답
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': f"<html><body><h1>{message}</h1><p>You can close this window.</p></body></html>"
        }

    except sfn.exceptions.TaskTimedOut:
        return {
            'statusCode': 410,
            'body': "⏳ 토큰이 만료되었습니다 (Task Timed Out)."
        }
    except sfn.exceptions.InvalidToken:
        return {
            'statusCode': 400,
            'body': "🚫 유효하지 않은 토큰입니다."
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Internal Server Error: {str(e)}"
        }

import boto3
import time
import json
from botocore.exceptions import ClientError # 에러 처리용 모듈 추가

ec2 = boto3.client('ec2')
autoscaling = boto3.client('autoscaling')

# ... (get_node_name_from_event 함수는 그대로 유지) ...
def get_node_name_from_event(event):
    if 'node_name' in event: return event['node_name']
    try:
        if 'falco' in event and 'kubernetes' in event['falco']:
            return event['falco']['kubernetes'].get('host')
    except: pass
    try:
        if 'falco' in event and 'output_fields' in event['falco']:
             return event['falco']['output_fields'].get('node')
    except: pass
    return None

def lambda_handler(event, context):
    print("Received Event:", json.dumps(event))
    
    node_name = get_node_name_from_event(event)
    if not node_name:
        return {"status": "error", "message": "No node_name provided"}

    print(f"Starting SOAR Response for Node: {node_name}")

    # ---------------------------------------------------------
    # 2. 식별 (Identify)
    # ---------------------------------------------------------
    try:
        response = ec2.describe_instances(Filters=[{'Name': 'private-dns-name', 'Values': [node_name]}])
        if not response['Reservations']:
            return {"status": "skipped", "reason": "Instance not found in EC2"}
        
        instance = response['Reservations'][0]['Instances'][0]
        instance_id = instance['InstanceId']
        asg_name = None
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'aws:autoscaling:groupName':
                asg_name = tag['Value']
                break
        print(f"Identified Instance ID: {instance_id}, ASG: {asg_name}")
    except Exception as e:
        return {"status": "error", "step": "identify", "error": str(e)}

    # ---------------------------------------------------------
    # 3. 대응 (Respond)
    # ---------------------------------------------------------
    snapshot_ids = []
    try:
        # A. Snapshot (기존 로직 유지)
        mappings = instance.get('BlockDeviceMappings', [])
        for mapping in mappings:
            vol_id = mapping['Ebs']['VolumeId']
            # 스냅샷은 중복 생성되어도 에러 안나므로 그냥 둠
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"[Falco Incident] Forensic snapshot for {instance_id}",
                TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [{'Key': 'CreatedBy', 'Value': '5entinel-SOAR'}]}]
            )
            snapshot_ids.append(snap['SnapshotId'])

        # B. ASG Standby (에러 핸들링 추가 부분!)
        if asg_name:
            print(f"Attempting to enter Standby: {instance_id}")
            try:
                autoscaling.enter_standby(
                    InstanceIds=[instance_id],
                    AutoScalingGroupName=asg_name,
                    ShouldDecrementDesiredCapacity=False
                )
                time.sleep(2)
            except ClientError as e:
                # "InService 상태가 아니다" 에러는 이미 격리된 것으로 간주하고 무시
                if "not in InService" in str(e):
                    print(f"Instance {instance_id} is not InService (likely already Standby or Stopped). Skipping ASG step.")
                else:
                    raise e # 다른 에러면 던짐
        
        # C. Stop Instance
        print(f"Stopping instance {instance_id}...")
        try:
            ec2.stop_instances(InstanceIds=[instance_id])
        except ClientError as e:
             # 이미 Stop 된 경우도 무시할 수 있지만 ec2.stop_instances는 멱등성(Idempotent)이 있어서 괜찮음
             print(f"Stop instance msg: {str(e)}")

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'Name', 'Value': f"FORENSIC-ISOLATED-{instance_id}"}, {'Key': 'Status', 'Value': 'Stopped_Suspicious'}]
        )

    except Exception as e:
        print(f"Response Error: {str(e)}")
        return {"status": "partial_error", "step": "respond", "error": str(e), "instance_id": instance_id}

    return {
        "status": "success",
        "node_name": node_name,
        "instance_id": instance_id,
        "asg_name": asg_name,
        "snapshots": snapshot_ids,
        "action_taken": "Snapshot + ASG Standby (Checked) + Stop"
    }

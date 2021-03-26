import ast
import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    
    instances = ast.literal_eval(os.environ['INSTANCES'])

    client = boto3.client('ec2')
    
    response = client.describe_instances(
        InstanceIds = instances
    )

    check = 'PASS'
    for instance in response['Reservations'][0]['Instances']:
        if instance['State']['Name'] != 'running':
            check = 'FAIL'
            break

    client = boto3.client('ssm')

    if check == 'PASS':
        client.send_command(
            Targets=[{
                'Key': 'InstanceIds',
                'Values': instances
            }],
            DocumentName='AWS-RunRemoteScript',
            DocumentVersion='1',
            TimeoutSeconds=600,
            Parameters={"sourceType":["GitHub"],"sourceInfo":["{\"owner\":\"4n6ir\",\"repository\":\"siphon-config\",\"getOptions\":\"commitID:fb2b64c8739dd39a1e29e9c23e7c06a0d233cca3\",\"path\":\"launch-siphon.sh\"}"],"commandLine":["launch-siphon.sh"],"workingDirectory":[""],"executionTimeout":["3600"]},
            MaxConcurrency='50',
            MaxErrors='0'
        )

        client = boto3.client('ssm')
        response = client.get_parameter(Name=os.environ['PARAMETER'])
        value = response['Parameter']['Value']

        client = boto3.client('events')
        response = client.disable_rule(Name=value)

    return {
        'statusCode': 200,
        'body': json.dumps('Siphon Configured!!')
    }
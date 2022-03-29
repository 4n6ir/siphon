import ast
import boto3
import json
import os

ssm_client = boto3.client('ssm')

def handler(event, context):

    instances = ast.literal_eval(os.environ['INSTANCE'])

    ssm_client.send_command(
        Targets = [{
            'Key': 'InstanceIds',
            'Values': instances
        }],
        DocumentName = 'AWS-RunRemoteScript',
        DocumentVersion = '1',
        TimeoutSeconds = 600,
        Parameters = {"sourceType":["S3"],"sourceInfo":["{\"path\":\"https://s3.amazonaws.com/"+os.environ['SCRIPTS3']+"/siphon.sh\"}"],"commandLine":["siphon.sh"],"workingDirectory":[""],"executionTimeout":["3600"]},
        MaxConcurrency = '50',
        MaxErrors = '0'
    )

    return {
        'statusCode': 200,
        'body': json.dumps('Siphon Configuration')
    }
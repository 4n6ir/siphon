import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambdaHandler(event, context):
    
    #objectname = event['Records'][0]['s3']['object']['key']
    print(event)    


    return {
        'statusCode': 200,
        'body': json.dumps('Zeek Log Parser')
    }
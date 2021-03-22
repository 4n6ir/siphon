import boto3
import gzip
import json
import logging
import os
import shutil

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambdaHandler(event, context):
    
    objects = event['Records'][0]['body']
    objectlist = json.loads(objects)
    objectname = objectlist['Records'][0]['s3']['object']['key'].replace('%3A', ':')
    
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DYNAMODB'])
    
    table.put_item(
        Item= {
            'pk': 'SIPHON#',
            'sk': 'SIPHON#'+objectname,
            'bucketname': os.environ['S3BUCKET'],
            'objectname': objectname,
            'status': 'STARTED'
        }
    )

    s3 = boto3.client('s3')

    s3.download_file(os.environ['S3BUCKET'], objectname, '/tmp/transfer.log.gz')

    with gzip.open('/tmp/transfer.log.gz', 'rb') as f_in, open('/tmp/gunzip.log', 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)




    
    s3.upload_file('/tmp/gunzip.log', os.environ['S3ARCHIVE'], objectname+'.parquet')
    
    return {
        'statusCode': 200,
        'body': json.dumps('Zeek Log Parser')
    }
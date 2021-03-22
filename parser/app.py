import boto3
import gzip
import json
import logging
import os
import shutil

import pandas as pd
import pyarrow
from datetime import timedelta
from zat.log_to_dataframe import LogToDataFrame

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def convert_timedelta_to_str(df):
    delta_columns = df.select_dtypes(include=['timedelta'])
    for column in delta_columns:
        df[column] = df[column].apply(tdelta_value_to_str)
    return df

def tdelta_value_to_str(value):
    if pd.isnull(value):
        return '-'  # Standard for Zeek null value
    else:
        return str(timedelta(seconds=value.total_seconds()))

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

    log_to_df = LogToDataFrame()
    
    zeek_df = log_to_df.create_dataframe('/tmp/gunzip.log')
    print('Dataframe Created: {:d} rows...'.format(len(zeek_df)))

    df = convert_timedelta_to_str(zeek_df)
    
    zeek_df.to_parquet('/tmp/transfer.parquet', compression='snappy', use_deprecated_int96_timestamps=True)
    
    s3.upload_file('/tmp/transfer.parquet', os.environ['S3ARCHIVE'], objectname+'.parquet')
    
    table.put_item(
        Item= {
            'pk': 'SIPHON#',
            'sk': 'SIPHON#'+objectname,
            'bucketname': os.environ['S3BUCKET'],
            'objectname': objectname,
            'status': 'COMPLETED'
        }
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps('Zeek Log Parser')
    }

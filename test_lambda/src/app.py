import boto3
import csv
import os
from datetime import datetime, timedelta
import io
from urllib.parse import urlparse

def assume_role(session, role_arn):
    sts = session.client('sts')
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='RDSMetricsSession'
    )
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

def get_metrics(cloudwatch, db_instance, start_time, end_time):
    metrics = {
        'WriteIOPS': ('AWS/RDS', 'WriteIOPS'),
        'WriteThroughput': ('AWS/RDS', 'WriteThroughput'),
        'ReadIOPS': ('AWS/RDS', 'ReadIOPS'),
        'ReadThroughput': ('AWS/RDS', 'ReadThroughput'),
        'CPUUtilization': ('AWS/RDS', 'CPUUtilization'),
        'DatabaseConnections': ('AWS/RDS', 'DatabaseConnections')
    }
    
    results = {}
    for metric_name, (namespace, metric) in metrics.items():
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance['DBInstanceIdentifier']}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 1 day
            Statistics=['p99']
        )
        if response['Datapoints']:
            results[metric_name] = max(point['p99'] for point in response['Datapoints'])
        else:
            results[metric_name] = 0
    
    return results

def lambda_handler(event, context):
    # Get environment variables
    role1_arn = os.environ['ROLE1_ARN']
    role2_name = os.environ['ROLE2_NAME']
    bucket = os.environ['S3_OUTPUT_BUCKET']
    path_prefix = os.environ['S3_OUTPUT_PATH'].strip('/')
    
    # Generate output key
    key = f"{path_prefix}/rds_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # Initialize sessions
    session = boto3.Session()
    role1_session = assume_role(session, role1_arn)
    
    # Initialize CSV output
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Account', 'Region', 'DBInstanceIdentifier', 'Engine', 'InstanceClass',
        'WriteIOPS', 'WriteThroughput', 'ReadIOPS', 'ReadThroughput',
        'CPUUtilization', 'DatabaseConnections'
    ])
    
    # Get list of regions
    ec2 = role1_session.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    
    # Get list of accounts
    org = role1_session.client('organizations')
    accounts = []
    paginator = org.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    
    end_time = datetime.now()
    start_time = end_time - timedelta(weeks=12)
    
    # Iterate through accounts and regions
    for account in accounts:
        account_id = account['Id']
        role2_arn = f'arn:aws:iam::{account_id}:role/{role2_name}'
        
        try:
            account_session = assume_role(role1_session, role2_arn)
            
            for region in regions:
                try:
                    rds = account_session.client('rds', region_name=region)
                    cloudwatch = account_session.client('cloudwatch', region_name=region)
                    
                    # Get RDS instances
                    paginator = rds.get_paginator('describe_db_instances')
                    for page in paginator.paginate():
                        for db in page['DBInstances']:
                            metrics = get_metrics(cloudwatch, db, start_time, end_time)
                            
                            writer.writerow([
                                account_id,
                                region,
                                db['DBInstanceIdentifier'],
                                db['Engine'],
                                db['DBInstanceClass'],
                                metrics['WriteIOPS'],
                                metrics['WriteThroughput'],
                                metrics['ReadIOPS'],
                                metrics['ReadThroughput'],
                                metrics['CPUUtilization'],
                                metrics['DatabaseConnections']
                            ])
                except Exception as e:
                    print(f"Error processing region {region} in account {account_id}: {str(e)}")
                    
        except Exception as e:
            print(f"Error assuming role in account {account_id}: {str(e)}")
    
    # Upload to S3
    s3 = role1_session.client('s3')
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=output.getvalue().encode('utf-8'),
        ContentType='text/csv'
    )
    
    return {
        'statusCode': 200,
        'body': f'CSV file uploaded to s3://{bucket}/{key}'
    }

import os
import boto3
from datetime import datetime, timedelta
import csv
import io
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Session cache to store assumed role sessions
_session_cache = {}

def assume_role(session, role_arn, external_id):
    """Assume an IAM role with caching"""
    cache_key = f"{role_arn}:{external_id}"
    
    # Check if we have a cached session
    if cache_key in _session_cache:
        return _session_cache[cache_key]
    
    logger.info(f"Attempting to assume role: {role_arn} with external ID: {external_id}")
    sts = session.client('sts')
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='RDSMetricsScanner',
            ExternalId=external_id
        )
        new_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        
        # Cache the new session
        _session_cache[cache_key] = new_session
        logger.info(f"Successfully assumed role {role_arn} and cached session")
        return new_session
    except Exception as e:
        logger.error(f"Failed to assume role {role_arn}: {str(e)}")
        raise

def get_metrics(cloudwatch, cluster, start_time, end_time):
    """Get CloudWatch metrics for an RDS cluster"""
    metrics = {
        'VolumeReadIOPs': ('AWS/RDS', 'VolumeReadIOPs'),
        'VolumeWriteIOPs': ('AWS/RDS', 'VolumeWriteIOPs'),
        'CPUUtilization': ('AWS/RDS', 'CPUUtilization'),
        'VolumeBytesUsed': ('AWS/RDS', 'VolumeBytesUsed'),
        'BufferCacheHitRatio': ('AWS/RDS', 'BufferCacheHitRatio')
    }
    
    results = {}
    for metric_name, (namespace, metric) in metrics.items():
        try:
            # Get p99 statistics (except for VolumeBytesUsed and BufferCacheHitRatio)
            if metric_name not in ['VolumeBytesUsed', 'BufferCacheHitRatio']:
                p99_response = cloudwatch.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric,
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster['DBClusterIdentifier']}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600*24*7,  # 7 days
                    ExtendedStatistics=['p99', 'p50']
                )
                
                if p99_response['Datapoints']:
                    results[f'{metric_name}_p99'] = max(point['ExtendedStatistics']['p99'] for point in p99_response['Datapoints'])
                    results[f'{metric_name}_p50'] = max(point['ExtendedStatistics']['p50'] for point in p99_response['Datapoints'])
                    results['DatapointCount'] = len(p99_response['Datapoints'])
                else:
                    results[f'{metric_name}_p99'] = 0
                    results[f'{metric_name}_p50'] = 0
            
            # Get average statistics
            avg_response = cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric,
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster['DBClusterIdentifier']}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600*24*7,  # 7 days
                Statistics=['Average']
            )
            
            if avg_response['Datapoints']:
                if metric_name == 'BufferCacheHitRatio':
                    # For BufferCacheHitRatio, take the minimum average
                    results[f'{metric_name}_avg'] = min(point['Average'] for point in avg_response['Datapoints'])
                else:
                    # For other metrics, take average of averages
                    results[f'{metric_name}_avg'] = sum(point['Average'] for point in avg_response['Datapoints']) / len(avg_response['Datapoints'])
            else:
                results[f'{metric_name}_avg'] = 0
                
        except Exception as e:
            logger.error(f"Error getting metric {metric_name} for {cluster['DBClusterIdentifier']}: {str(e)}")
            if metric_name not in ['VolumeBytesUsed', 'BufferCacheHitRatio']:
                results[f'{metric_name}_p99'] = 0
                results[f'{metric_name}_p50'] = 0
            results[f'{metric_name}_avg'] = 0
    
    return results

def process_cluster(account_session, region, cluster, start_time, end_time):
    """Process a single RDS cluster"""
    try:
        cloudwatch = account_session.client('cloudwatch', region_name=region)
        metrics = get_metrics(cloudwatch, cluster, start_time, end_time)
        
        return [
            cluster.get('AccountId', ''),
            region,
            cluster.get('DbClusterResourceId', '').lower(),
            cluster['DBClusterIdentifier'],
            cluster.get('Engine', ''),
            cluster.get('EngineVersion', ''),
            cluster.get('DatabaseName', ''),
            cluster.get('Status', ''),
            metrics.get('VolumeReadIOPs_p99', 0),
            metrics.get('VolumeReadIOPs_p50', 0),
            metrics.get('VolumeReadIOPs_avg', 0),
            metrics.get('VolumeWriteIOPs_p99', 0),
            metrics.get('VolumeWriteIOPs_p50', 0),
            metrics.get('VolumeWriteIOPs_avg', 0),
            metrics.get('CPUUtilization_p99', 0),
            metrics.get('CPUUtilization_p50', 0),
            metrics.get('CPUUtilization_avg', 0),
            metrics.get('VolumeBytesUsed_avg', 0),
            metrics.get('BufferCacheHitRatio_avg', 0),
            metrics.get('DatapointCount', 0)
        ]
    except Exception as e:
        logger.error(f"Error processing cluster {cluster['DBClusterIdentifier']} in {region}: {str(e)}")
        return None

def process_region(account_session, account_id, region, start_time, end_time):
    """Process all clusters in a region"""
    try:
        logger.info(f"Processing region {region}")
        rds = account_session.client('rds', region_name=region)
        
        clusters = []
        paginator = rds.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster['AccountId'] = account_id  # Add account ID to cluster data
                clusters.append(cluster)
        
        logger.info(f"Found {len(clusters)} clusters in {region}")
        return clusters
    except Exception as e:
        logger.error(f"Error processing region {region}: {str(e)}")
        return []

def process_account(finder_session, account_id, role_name, external_id, start_time, end_time):
    """Process all regions in an account"""
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    logger.info(f"Processing account {account_id} with role {role_arn}")
    
    try:
        account_session = assume_role(finder_session, role_arn, external_id)
        
        # Get list of regions
        logger.info("Getting list of AWS regions...")
        ec2 = finder_session.client('ec2')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        logger.info(f"Found regions: {regions}")
        
        # Process regions in parallel
        clusters = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_region = {
                executor.submit(process_region, account_session, account_id, region, start_time, end_time): region
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    region_clusters = future.result()
                    clusters.extend(region_clusters)
                except Exception as e:
                    logger.error(f"Error processing region {region}: {str(e)}")
        
        return clusters
    except Exception as e:
        logger.error(f"Error processing account {account_id}: {str(e)}")
        return []

def lambda_handler(event, context):
    # Get environment variables
    role_name = os.environ['ROLE_NAME']
    bucket = os.environ['S3_BUCKET']
    path_prefix = os.environ['S3_PATH'].strip('/')
    
    # Get external ID from payload
    external_id = event.get('EXTERNAL_ID')
    if not external_id:
        raise ValueError("EXTERNAL_ID must be provided in the payload")
    
    logger.info(f"Starting RDS cluster metrics collection with role: {role_name}")
    logger.info(f"S3 destination: s3://{bucket}/{path_prefix}")
    
    # Get credentials from payload
    logger.info("Setting up finder session...")
    finder_session = boto3.Session(
        aws_access_key_id=event['FINDER_ACCESS_KEY'],
        aws_secret_access_key=event['FINDER_SECRET_KEY'],
        aws_session_token=event['FINDER_SESSION_TOKEN']
    )
    
    logger.info("Setting up writer session...")
    writer_session = boto3.Session(
        aws_access_key_id=event['WRITER_ACCESS_KEY'],
        aws_secret_access_key=event['WRITER_SECRET_KEY'],
        aws_session_token=event['WRITER_SESSION_TOKEN']
    )

    accounts = event['ACCOUNTS'].split(',')
    logger.info(f"Processing accounts: {accounts}")
    
    # Generate output key
    key = f"{path_prefix}/rds_cluster_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    logger.info(f"Output file will be: {key}")
    
    # Create CSV buffer
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'AccountId', 'Region', 'DbClusterResourceId', 'ClusterIdentifier', 'Engine', 'EngineVersion',
        'DatabaseName', 'Status', 'VolumeReadIOPs_p99', 'VolumeReadIOPs_p50', 'VolumeReadIOPs_avg',
        'VolumeWriteIOPs_p99', 'VolumeWriteIOPs_p50', 'VolumeWriteIOPs_avg', 'CPUUtilization_p99',
        'CPUUtilization_p50', 'CPUUtilization_avg', 'VolumeBytesUsed_avg', 'BufferCacheHitRatio_avg',
        'DatapointCount'
    ])

    end_time = datetime.now()
    start_time = end_time - timedelta(weeks=12)
    logger.info(f"Collecting metrics from {start_time} to {end_time}")
    
    # Process accounts in parallel
    all_clusters = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_account = {
            executor.submit(process_account, finder_session, account_id, role_name, external_id, start_time, end_time): account_id
            for account_id in accounts
        }
        
        for future in as_completed(future_to_account):
            account_id = future_to_account[future]
            try:
                account_clusters = future.result()
                all_clusters.extend(account_clusters)
            except Exception as e:
                logger.error(f"Error processing account {account_id}: {str(e)}")
    
    # Process clusters in parallel
    logger.info(f"Processing metrics for {len(all_clusters)} clusters")
    rows = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_cluster = {
            executor.submit(process_cluster, assume_role(finder_session, f'arn:aws:iam::{cluster["AccountId"]}:role/{role_name}', external_id), 
                          cluster['AvailabilityZones'][0][:-1], cluster, start_time, end_time): cluster
            for cluster in all_clusters
        }
        
        for future in as_completed(future_to_cluster):
            cluster = future_to_cluster[future]
            try:
                row = future.result()
                if row:
                    rows.append(row)
            except Exception as e:
                logger.error(f"Error processing cluster {cluster['DBClusterIdentifier']}: {str(e)}")
    
    # Write all rows
    for row in rows:
        writer.writerow(row)
    
    # Upload to S3
    logger.info(f"Uploading results to s3://{bucket}/{key}")
    s3 = writer_session.client('s3')
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=output.getvalue().encode('utf-8'),
            ContentType='text/csv'
        )
        logger.info("Upload successful")
    except Exception as e:
        logger.error(f"Error uploading to S3: {str(e)}")
        raise
    
    return {
        'statusCode': 200,
        'body': f'Successfully wrote metrics to s3://{bucket}/{key}'
    }

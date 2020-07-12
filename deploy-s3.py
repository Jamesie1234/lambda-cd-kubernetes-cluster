import logging
import boto3
import os
import shutil
import json
import time
import bz2
import tarfile

from botocore.vendored import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):

    try:
        env = event['env']
        logger.info(f'env: {env}')
        version = event['version']
        logger.info(f'version: {version}')

        project_name = 'web-ui'

        if (env == 'development') or (env == 'dev') or (env == 'testing') or (env == 'qa'):
            branch = 'develop'
        elif (env == 'stg1') or (env == 'stg2') or (env == 'perf') or (env == 'prod'):
            branch = 'master'
        
        if branch:
            logger.info(f'branch: {branch}')
            return deploy_to_s3(project_name, env, branch, version)
        else:
            print('S3 Bucket deployment cannot be completed. Environment {env} does not exist')

    except Exception as e:
        return {
            'statusCode': 400,
            'body': str(e)
        }



workingDirectory = '/tmp/deploy-image'
lambdaHome = os.getcwd()


def deploy_to_s3(project_name, env, branch, version):

    prep_working_directory()
    file_path = download_build_from_drive('ui-build-drive', calculate_source_file_name(project_name, branch, env, version))
    output_path = unpack_to_disk(file_path, 'output')
    install_binaries()
    upload_to_s3_bucket(calculate_s3_bucket_name(env), output_path)

    return {
        'statusCode': 200,
        'body': json.dumps('Deployment to S3 succeeded')
    }

def prep_working_directory():
    shutil.rmtree(workingDirectory, ignore_errors=True)
    os.mkdir(workingDirectory)
    os.chdir(workingDirectory)
    logger.info(f'Updated working directory to {workingDirectory}')


def download_build_from_drive(s3_bucket_name, source_file_name):
    logger.info(f'Downloading : {source_file_name} from S3 Bucket[{s3_bucket_name}]')
    S3 = boto3.client('s3')
    S3.download_file(s3_bucket_name, source_file_name, source_file_name)
    logger.info(f'Download completed : {source_file_name} from S3 Bucket[{s3_bucket_name}]')
    return source_file_name

def calculate_s3_bucket_name(env):
    if (env == 'development') or (env == 'dev'):
        return 'web.dev.luxon-pay.com'
    elif (env == 'testing') or (env == 'qa'):
        return 'web.qa.luxon-pay.com'
    elif (env == 'stg1'):
        return 'web.stg1.luxon-pay.com'
    elif (env == 'stg2'): 
        return 'web.stg2.luxon-pay.com'
    elif (env == 'perf'):
        return 'web.perf.luxon-pay.com'
    #elif (env == 'prod'):
    #    return 'web.luxon-pay.com'

def calculate_source_file_name(project_name, branch, env, version):
    return project_name + '-' + branch + '-' + version + '.tar.gz' 

def unpack_to_disk(path, output_path):
    tar = tarfile.open(path)
    tar.extractall(output_path)
    logger.info(f'{path} Archive file is extracted to {output_path}.')

    return output_path

def install_binaries():
    logger.info("Lambda home directory: " + lambdaHome)

    os.environ['PATH'] += ":" + os.path.join(lambdaHome)
    logger.info(f'Updated environment path to {os.environ["PATH"]}')


def upload_to_s3_bucket(s3_bucket_name, upload_dir):
    logger.info(f'Uploading {upload_dir} dir content to S3 Bucket[{s3_bucket_name}]')
    S3 = boto3.client('s3')

    for root, dirs, files in os.walk(upload_dir):
        nested_dir = root.replace(upload_dir, '')
        if nested_dir:
            nested_dir = nested_dir.replace('/', '', 1) + '/'

        for file in files:
            complete_file_path = os.path.join(root, file)
            file = nested_dir + file if nested_dir else file
            S3.upload_file(complete_file_path, s3_bucket_name, file)
    logger.info(f'Upload completed : {upload_dir} dir content to S3 Bucket[{s3_bucket_name}]')
    # trigger cloudfront invalidation
    invalidate_cloudfront_cache(s3_bucket_name)


def invalidate_cloudfront_cache(url):
    logger.info(f'Invalidating cloudfront url: {url}')
    client = boto3.client('cloudfront')
    distribution_id = get_cloudfront_distribution_id(url)
    logger.info(f'Found Cloudfront distributionId: {distribution_id} for url: {url}')
    response = client.create_invalidation(
        DistributionId=distribution_id,
        InvalidationBatch={
            'Paths': {
                'Quantity': 1,
                'Items': [
                    '/*'
                    ],
                },
            'CallerReference': str(time.time()).replace(".", "")
            }
        )
    logger.info(f'Invalidation completed cloudfront url: {url}')
    
def get_cloudfront_distribution_id(url):
    logger.info(f'Finding Cloudfront distributionId for url: {url}')
    client = boto3.client('cloudfront')

    paginator = client.get_paginator('list_distributions')
    response_iterator = paginator.paginate()
    logger.info('Iterating thru Cloudfront list_distributions results')
    for i in response_iterator:
        for j in i['DistributionList']['Items']:
            if j['Aliases']['Items'][1] == url:
                return j['Id']

##test the handler function
# event = {
#     'env': 'testing',
#     'version': '1.5.3-0',
# }
# lambda_handler(event, "null")

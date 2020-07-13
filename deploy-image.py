import sys
import logging
from botocore.vendored import requests
import os
import shutil
import json

import bz2
import tarfile
import subprocess

import boto3
import base64
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# # For local test execution
# handler = logging.StreamHandler(sys.stdout)
# handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
# logger.addHandler(handler)

def lambda_handler(event, context):

    try:
        env = event['env']
        logger.info(f'env: {env}')
        tag = event['tag']
        logger.info(f'tag: {tag}')

        if (env == 'development') or (env == 'testing') or (env == 'qa'):
            tag = 'develop-latest'
            return deploy_image(env,tag)
        elif (env == 'stg1') or (env == 'stg2') or (env == 'perf') and (tag == ""):
            tag = 'develop-latest'
            return deploy_image(env,tag)
        elif (env == 'stg1') or (env == 'stg2') or (env == 'perf') or (env == 'prod') or (env == "trplmrs"):
            return deploy_image(env,tag)
        else:
            print('Deployment cannot be effected. Environment {env} does not exist')

    except Exception as e:
        return {
            'statusCode': 400,
            'body': str(e)
        }



workingDirectory = '/tmp/deploy-image'
lambdaHome = os.getcwd()


def deploy_image(env, tag):
    prep_working_directory()
    content = download_bitbucket_commit()
    unpack_to_disk(content)
    install_binaries()
    configure_kubectl(env)
    path = find_repo_root()
    execute_deployment_script(path,env,tag)

    return {
        'statusCode': 200,
        'body': json.dumps('Deployment succeeded')
    }


def prep_working_directory():
    shutil.rmtree(workingDirectory, ignore_errors=True)
    os.mkdir(workingDirectory)
    os.chdir(workingDirectory)
    logger.info(f'Updated working directory to {workingDirectory}')


def download_bitbucket_commit():

    # secretJson = get_secret("BitbucketCredentials", "eu-west-1")
    # secret = json.loads(secretJson)
    # username = secret["BITBUCKET_USERNAME"]
    # password = secret["BITBUCKET_PASSWORD"]
    username ='jadesanlu'
    password ='Adetunji1997'

    archive_url = f'https://{username}:{password}@bitbucket.org/luxonpay/helm/get/HEAD.tar.bz2'
    logger.info('Requesting source from Bitbucket...')
    response = requests.get(archive_url)
    logger.info(f'Response status code: {response.status_code}')
    return response.content


def unpack_to_disk(content):
    unzipped = bz2.decompress(content)
    open('./repo.tar', 'wb').write(unzipped)
    tar = tarfile.open('./repo.tar')
    tar.extractall()
    logger.info('Commit has been unpacked to disk.')

def find_repo_root():
    ls = os.listdir()
    prefix = 'luxonpay-helm'
    repo_root = next(item for item in ls if item[:len(prefix)] == prefix)
    logger.info(f'Repository root folder: {repo_root}')
    return repo_root

def install_binaries():
    logger.info("Lambda home directory: " + lambdaHome)

    os.environ['PATH'] += ":" + os.path.join(lambdaHome)
    logger.info(f'Updated environment path to {os.environ["PATH"]}')


def configure_kubectl(env):
    # secretJson = get_secret(f'KubernetesCredentials-{env}', "eu-west-1")
    # secret = json.loads(secretJson)
    # KUBE_CA = base64.b64decode(secret["KUBE_CA"]).decode('utf-8')
    # KUBE_CLIENT_CERT = base64.b64decode(secret["KUBE_CLIENT_CERT"]).decode('utf-8')
    # KUBE_CLIENT_KEY = base64.b64decode(secret["KUBE_CLIENT_KEY"]).decode('utf-8')
    # KUBE_CLUSTER=secret["KUBE_CLUSTER"]
    # KUBE_SA=secret["KUBE_SA"]
    # KUBE_SERVER=secret["KUBE_SERVER"]

    open(f'{workingDirectory}/kube_ca.crt', 'wt').write(KUBE_CA)
    open(f'{workingDirectory}/kube_client.crt', 'wt').write(KUBE_CLIENT_CERT)
    open(f'{workingDirectory}/kube_client.key', 'wt').write(KUBE_CLIENT_KEY)

    os.environ['KUBECONFIG'] = f'{workingDirectory}/config'

    setClusterCmd = f'kubectl config set-cluster {KUBE_CLUSTER} --server={KUBE_SERVER} --certificate-authority={workingDirectory}/kube_ca.crt'
    subprocess.call(setClusterCmd, shell=True)

    setCredentialsCmd = f'kubectl config set-credentials {KUBE_SA} --client-certificate={workingDirectory}/kube_client.crt --client-key={workingDirectory}/kube_client.key'
    subprocess.call(setCredentialsCmd, shell=True)

    setContextCmd = f'kubectl config set-context {KUBE_CLUSTER} --cluster={KUBE_CLUSTER} --user={KUBE_SA}'
    subprocess.call(setContextCmd, shell=True)

    useContextCmd = f'kubectl config use-context {KUBE_CLUSTER}'
    subprocess.call(useContextCmd, shell=True)

    logger.info('Configured kubectl.')

    os.environ["HELM_HOME"] = f'{workingDirectory}/helm'

    logger.info(f'{workingDirectory}/helm')

    helmInitCmd = f'helm init --client-only'
    subprocess.call(helmInitCmd, shell=True)

    logger.info(' helm init done.')

    installSecretsCmd = f'cp -R {lambdaHome}/helm-secrets {workingDirectory}/helm/plugins/helm-secrets'
    subprocess.call(installSecretsCmd, shell=True)

    installSecretsCmd = f'cp -R {lambdaHome}/helm-secrets {workingDirectory}/helm/plugins/helm-secrets'
    subprocess.call(installSecretsCmd, shell=True)
    logger.info(installSecretsCmd)

    logger.info('Configured helm.')


#def execute_deployment_script(path, commit, env):
def execute_deployment_script( path, env, tag):
    os.chdir(path)
    script_path = './.pipeline/deploy.sh'
    os.chmod(script_path, 0o755)
    logger.info(f'ImageTag: {tag}')
    logger.info(f'Environment: {env}')
    deployCommand = f'{script_path} {env} {tag}'
    logger.info(f'Executing: {deployCommand}')
    output = subprocess.check_output(deployCommand, shell=True)
    logger.info(f'Output: {output}')
    helmListOutput = subprocess.check_output('helm list', shell=True)
    logger.info(f'helm list: {helmListOutput}')


def get_secret(secret_name, region_name):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.


    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )

    # Decrypts secret using the associated KMS CMK.
    # Depending on whether the secret is a string or binary, one of these fields will be populated.
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
        return secret
    else:
        decoded_binary_secret = base64.b64decode(
            get_secret_value_response['SecretBinary'])
        return decoded_binary_secret

# For local test execution
#deploy_image('development', 'develop:latest')


#test the handler function
event = {
   'env': 'stg1',
   'tag': '',
}
lambda_handler(event, "null")

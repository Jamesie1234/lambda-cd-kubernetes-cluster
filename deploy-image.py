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
    
    
    #stg1 
    KUBE_CA = base64.b64decode("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWJ1Z0F3SUJBZ0lNRlgwaDRzWWhRTkJiS3hwRk1BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1Ua3dNVEl6TVRVME5UQTBXaGNOTWprd01USXlNVFUwTlRBMApXakFWTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQXpvVjdQb0JCUUpHRUhjZU9HYXhPY1RIVm1FTjFsMklOTEtic0dQZG1IaXVacVU2bkREMEQKSnpHR3RsYXZ1UFJPTHpTaXVVL2pUcVg0eFZkQXA0U2NNOWpBb1lUTWNoV2hvaWVFMXlzVW5wekVBUi9HTTJPSApzR01yemtpZ0pDeElsSkE0elFCN25yK2owb01QNzRra3RkSVZDWUUvc1lPOW5Sb0o3bVU3SFRaSVR4VTJ4Q0ZZClY1eDlaOWUyYm9vR0lPSVA1V1AyVFNlaHNXa0FIbCtpRDZyTVdPT3JXbndBa3RZQm91Q0MwTisvMEhsc3Y5ZFMKSkYxMDRXY2RuWE5sK0dTS0VEbEJ2MnY5QTJyZ3lLSk1pQjhRYW05ZC9Mek01dHNGVVJidlZta1Z5RTRORXVUeApKeEJkMktTR0M3NmJ3UkdYNVUxV1VGa3licHdjU1orM2F3SURBUUFCb3lNd0lUQU9CZ05WSFE4QkFmOEVCQU1DCkFRWXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUF5em44aEUvY1FxLzIKQTZtZzlSUTh0bmxiTWx4WWo4S2pYc0c1TTdKUm9KUWIyUnZFSlh0WFI2Q1JPZnIvWDlEUVFjNzVpbUo2RDk4Tgp3ZVNLR3VTY2I3MWRpdXJOc3MvTmtZcitIMnM4M0lmQ24wbWU4TlVHcFRvRU5GOHhyb3dMaWNZR3JRS29MVldSCkNVbTJhZVpya0JJNEdndGxBTWdjbVFuN2ZGSDVYaU5ibWxvcWFWUGxBN05YU1dicXpBM2p2YXFWWDdLei9XM2IKQlNNNkF4dHhtdXEwbmVuSFdmMG5YM2R5THZ5cC9BdUR2ZkEyTkdKaVZqZUxsVG9VT0xrQzU1WkduUVZYTWVQMApPUDhBRVB6QitSR3doeUZGZFZGdldOMUxTWVFMZlVodXFUbTRSUFl0UUhpVjRPdjRZM1FKZlNQSWc0bzlJK3orCjZHakZ0ZjRNdUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==").decode('utf-8')
    KUBE_CLIENT_CERT = base64.b64decode("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMrekNDQWVPZ0F3SUJBZ0lNRlgwaDQzSFZkd0NIbFNBNU1BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1Ua3dNVEl6TVRVME5UQTRXaGNOTWprd01USXlNVFUwTlRBNApXakFyTVJjd0ZRWURWUVFLRXc1emVYTjBaVzA2YldGemRHVnljekVRTUE0R0ExVUVBeE1IYTNWaVpXTm1aekNDCkFTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTVFVcVozaFIzcCtuQ3YzUEhYcHRUVXUKWDRhZVZhYlFoUXpSdUpNdzlCVGY1L3MvZU1keTdEdklCVm5MUDNzYzlONzNibm5BSy9nd3l3ZW94Z0phV0dZYQphOUxhbU11dVV5dm90L1RiQkMyZzVmWVViOERuaFlhaDAvaVVobXlkMDNuMThTTU9Nc2V2NHlWb0hnRXdzcFRJCnZTSEM2RTFBYkFCSEo2Y2RpZWZ0YmxGYjdWNXdVVGVKQ2duWmVDWG0xRS8wSHdtYWFBMVZGMmwvTmRPOXM0MEUKalVBSnhaRy92Z3pUbkVTTFVQa2xjQjdaZ1dRT1puZ2dSVU8wNldHMDBqc05YazBhNzV0S3QzZEFLbzZNVnFlKwo1OTJjTGpSMm0yckJ2SzRaL0ZVUHZ0c2pyYndMb3JReU0wcXQxajBZV0krblZwS2dmRWVDYmJNRnpZKzBtMzBDCkF3RUFBYU0xTURNd0RnWURWUjBQQVFIL0JBUURBZ2VBTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQ01Bd0cKQTFVZEV3RUIvd1FDTUFBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFHeExzbExjZlFjZ2dNUTAwTHlNTEFnVApCd1lScU5LbWZ5K3ZtRXQyYzBGOE8ybjMxNnNBUWp6c3Rab3BCd1paSVZzZEt6NkljMlJPZk4xY1p1eHVSSTNoCmhzcEY4ZkpLdHV2MTRvYVBBWjJlMldMcGVtZnRQSjFBRkdhRy9XOCtiR2FWMGZzVnE0c1hVVTQ3a1pPeUpmbE4Kd0pmZFgrZXFpVk9YWkZCbGYyc2JacXZZcndyQmlmRENZMkloOHVzd0pwelVaTHp3amRUQTVpWGJxSkVaTEFodgo5cTBQNHEwbDIrck1nWlhXZElqUWtwSGtMRUNSZzV0VHJ1ZkZEME1rZGI3TmZvTWp6eGs2NFMwREdqQThLZHgyCkNMYTlnZlM2V1BXaFF6S2lvRC9YS0w2M0JlTTg0ODQxM0d1ZTloREd4Z1VicnVlenNMK1dYUG9VaWQ1WXRJST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=").decode('utf-8')
    KUBE_CLIENT_KEY = base64.b64decode("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBeEJTcG5lRkhlbjZjSy9jOGRlbTFOUzVmaHA1VnB0Q0ZETkc0a3pEMEZOL24rejk0CngzTHNPOGdGV2NzL2V4ejAzdmR1ZWNBcitERExCNmpHQWxwWVpocHIwdHFZeTY1VEsraTM5TnNFTGFEbDloUnYKd09lRmhxSFQrSlNHYkozVGVmWHhJdzR5eDYvakpXZ2VBVEN5bE1pOUljTG9UVUJzQUVjbnB4Mko1KzF1VVZ2dApYbkJSTjRrS0NkbDRKZWJVVC9RZkNacG9EVlVYYVg4MTA3MnpqUVNOUUFuRmtiKytETk9jUkl0UStTVndIdG1CClpBNW1lQ0JGUTdUcFliVFNPdzFlVFJydm0wcTNkMEFxam94V3A3N24zWnd1TkhhYmFzRzhyaG44VlErKzJ5T3QKdkF1aXRESXpTcTNXUFJoWWo2ZFdrcUI4UjRKdHN3WE5qN1NiZlFJREFRQUJBb0lCQVFDSm1FcFNiUFRBdzdvSgpyQ3YwUG5VWGhad3BGbERhaDNibVFRRDU0UjlXeXF5NmhaYld0eEdJL2RxcllWSUJyWmMwSTRPVjBrSEluMHpKCjZpaFJIRjd0LzFwc2sxTW5rd1B3U3hWVHNLRms5NFNIdzEyTWk2c0toK0w4akJVc2dUQVdaSHk3Y2NvMmtIbWcKRlVrQTR0QmVVZU5PbnJ4dkFXY0ladVl2Z2kzMDNsQlpaOHMvTlZDV3JNODE2bkRzSnFwSFNKU3hsWUJWZkNhbQp2N3gvV2FzcGZlM09yYkpOazlmUzh2QTM5dHlQUEFXdmlMTitwNDlrdHFFeDNaMUJYUWs0bHhxdWp5eU9tci9tCktmaFpyMDBiOWx3bWNrZzlKTG5UUXhCMUxhblQwTThrS0N0Q3JMd1VIaUcxb0FsMkloSyszd21keDhrVUUyOUwKTmtLMGMrd0JBb0dCQU5Pc0ExczZKUjExV0NYcmx4Q2VFbHE5VkxyQnpVYUEyaGRiV3JkTHROZ1dQQ1VBa1laQgo4amdyUlpaT2k4U0ZyVlNhOFhSZ1A0OVNBeHlsazFWWnl0akhKa2drc1BZaEFTUXI0WVphOFZHQTNxWG5TemRsCjhPUTJNKzR4QnhZdEptNEEwby9paUFnNmVxUWlLQzYwcXVlbE1aNDFSWEdYVncrYk56THhidDU5QW9HQkFPMGsKeVNhUzR3Wjl6eTB4R3FZbXBWb0hBNjNFNWJKWitQUW8rM2VwYXBCbDhCNElCTDNWRUsvTVlCa3I4QW1ObWRNVApIV2xmZ1dNZnNLSTlDOHBFRTFwWE1iWE84Q1QyL00zbVJyM0prSkttN1NCOGJGTlBLOGhjaUpOYWtPejQ1Zm5rCmNqMmxpM2huUjRuNHZCUDltRVZScDFxNE9qQlRDY2JsZUtKNWFFRUJBb0dBUy9pM0U2MGcyUnZlMFcxblFOMmIKTk5vemFQeGFFdTM0V04yL0IzNnluOFFMUGpTZ0JwSHd2OXc0RTZTSlliV2c2bmJhSnF6TTQwSEtRQ1BsWjRMYwozVVZOSmlPVktDSGNhUUVlNXJ3SlZQbHQ4Qm05MDFwUlJYZDIyQXpjd0ViZ1BpY3BhOThnZCtPVlZRZTFhRjRMCjRTeFhUTE5PQTJFUUxGZkhUZzk5ZlhrQ2dZQWtIYThZMWRRSGdBK1daVjBXb3RvWjdPbU5oR2dyRW5MTTFKVC8KczJpTVYwb0xlTk1vQ2hRQmdoRzhvNmxwK3d2TFRxVHpFRjJIT0NOUmdoU1NtRzJPRzZ0eGNmTzIzWHJBN09vbgpLMVIrVVRmWjg3a1hzdjRMQkxTMEpGM2dDVVFWRzhxZVF1RUwxRWJiNTJyVmJKRE5OZE5VQ0t5c0FXbUN4aDNxCk9LMDlBUUtCZ1FEVEhmVFZVc1JDRU1hRkxTOXpITmZVQ1JHL3ZxTG4raWZZVWZpV1ZnWHhPcmlST1lXSk5POUgKTU9WaVl6VFFmVkJIaUZhRFJvd3N6UXIxanlJK3dDNndnYlNlckhCVWQ3U0RlQzlEQTJQN3lDRkVLMzIxRDZZeApKNHk1cWs4MXpYVzl0ZDY3Z3h3K0owdzlRRElmWDBjYVB4MEdueUdZQ25NaXVQOWJ2alhyZUE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=").decode('utf-8')
    KUBE_CLUSTER="local"
    KUBE_SA="kubecfg"
    KUBE_SERVER="https://api-stg1-luxon-pay-com-tk2bkr-1479010048.eu-west-1.elb.amazonaws.com"


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

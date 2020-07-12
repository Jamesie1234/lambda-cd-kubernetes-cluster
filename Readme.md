# DeployImage lambda

## Description

This lambda function is responsible for deploying components (related to a Bitbucket repository) into the Kubernetes clusters.

The lambda will:
- Download a snapshot of a helm repositorys latest version
- Unpack the helm repo into the tmp folder
- Configure kubectl for the specified environment
- Execute the deploy.sh script in the root of the repository

It accepts the following mandatory arguments:
- env - environment to update (i.e. development, testing)

## Configuration

The lambda function is dependent upon 2 sets of "Secrets"; `BitbucketCredentials` and `KubernetesCredentials-<env>`

The `BitbucketCredentials` secret must contain the following keys:
- BITBUCKET_USERNAME
- BITBUCKET_PASSWORD

A `KubernetesCredentials<env>` secret must be created for each environment and contain the following keys:
- KUBE_CLUSTER - Name of the cluster
- KUBE_SERVER - Url of the clusters API
- KUBE_CA - The cluster's certificate-authority certificate
- KUBE_SA - Username with access rights to update the cluster
- KUBE_CLIENT_CERT - The user's client certificate
- KUBE_CLIENT_KEY - The user's client key

## Implementation

The lambda function consists of a python script and multiple binaries:
- deploy-image.py
- kubectl
- helm
- sops

## Function Deployment

Use the `update-deploy-image.sh` script to build generate the lambda zip file and upload to AWS. The binaries are copied from the /usr/local/bin folder and must already be installed on the local machine (and be compatible with the Amazon Linux AMI).

Note that  there is also an amazon linux container image which is pushed to luxon-payments' ECR account. The image is ; 
* 004671885525.dkr.ecr.eu-west-1.amazonaws.com/bp/cd_lambda


# DeployS3Bucket lambda

This function is responsible for web-ui build S3 bucket deployments.

The lambda will:
- Download the build tar file from ui-build-drive S3 bucket
- Unpack the tar file 
- Upload the files to target env S3 bucket
- Invalidate the CloudFront caches

It accepts the following mandatory arguments:
- env - environment to update (i.e. development, testing)
- version - version to be deployed
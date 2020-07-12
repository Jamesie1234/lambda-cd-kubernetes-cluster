#!/bin/bash

FUNCTION_NAME="$1"

if [ -z "$FUNCTION_NAME" ]; then
  echo Please give your Lambda-function a name EG create_lambda_function.sh my-function
  exit 1
fi


ln -s ~/.helm/plugins/helm-secrets/ helm-secrets
ln -s /home/devops/luxon-repo/helm-new/ helm


zip deploy-image.zip deploy-image.py /usr/bin/kubectl /home/devops/snap/helm /usr/local/bin/sops -j
zip deploy-image.zip helm-secrets/*

aws lambda create-function --function-name $FUNCTION_NAME \
   --zip-file fileb://deploy-image.zip --handler deploy-image.lambda_handler --runtime python3.7 --timeout 30 --memory-size 512 \
   --role arn:aws:iam::666085507687:role/DeployImageRole --region eu-west-1


rm helm-secrets
rm helm
rm deploy-image.zip

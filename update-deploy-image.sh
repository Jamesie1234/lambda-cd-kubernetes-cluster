#!/bin/bash

ln -s ~/.helm/plugins/helm-secrets/ helm-secrets
ln -s ~/dev/luxon/helm helm


zip deploy-image.zip deploy-image.py /usr/local/bin/kubectl /usr/local/bin/helm /usr/local/bin/sops -j
zip deploy-image.zip helm-secrets/*
aws lambda update-function-code --function-name DeployImage --zip-file fileb://deploy-image.zip

rm helm-secrets
rm helm
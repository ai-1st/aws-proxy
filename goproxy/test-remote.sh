#!/bin/bash

scp ubuntu@ec2-3-82-61-52.compute-1.amazonaws.com:/home/ubuntu/aws-proxy/goproxy/build/aws-proxy.crt certs/
scp ubuntu@ec2-3-82-61-52.compute-1.amazonaws.com:/home/ubuntu/aws-proxy/goproxy/build/aws-proxy.key certs/

export HTTP_PROXY=http://ec2-3-82-61-52.compute-1.amazonaws.com:8080
export HTTPS_PROXY=http://ec2-3-82-61-52.compute-1.amazonaws.com:8080
export AWS_CA_BUNDLE=certs/aws-proxy.crt

aws s3 ls

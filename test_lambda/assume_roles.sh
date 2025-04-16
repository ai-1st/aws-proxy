#!/bin/bash
set -e

source env/set_vars.sh

# Get finder credentials (two-step assume role)
echo "Getting finder credentials..."
finder_temp=$(aws sts assume-role \
    --role-arn "$FINDER_ROLE_ARN" \
    --role-session-name "FinderStep1" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)

IFS=$'\t' read -r TEMP_ACCESS_KEY TEMP_SECRET_KEY TEMP_SESSION_TOKEN <<< "$finder_temp"

echo Assumed 1

# Use temporary credentials to assume the second role
finder_temp2=$(AWS_ACCESS_KEY_ID="$TEMP_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$TEMP_SECRET_KEY" \
    AWS_SESSION_TOKEN="$TEMP_SESSION_TOKEN" \
    aws sts assume-role \
    --role-arn "$FINDER_ROLE2_ARN" \
    --external-id "$FINDER_ROLE2_EXTERNAL_ID" \
    --role-session-name "$SESSION_NAME" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)

IFS=$'\t' read -r TEMP2_ACCESS_KEY TEMP2_SECRET_KEY TEMP2_SESSION_TOKEN <<< "$finder_temp2"
echo Assumed 2

# Get finder credentials (three-step assume role)
finder_creds=$(AWS_ACCESS_KEY_ID="$TEMP2_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$TEMP2_SECRET_KEY" \
    AWS_SESSION_TOKEN="$TEMP2_SESSION_TOKEN" \
    aws sts assume-role \
    --role-arn "$FINDER_ROLE3_ARN" \
    --role-session-name "RDSFinder" \
    --duration-seconds 3600 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)

IFS=$'\t' read -r FINDER_ACCESS_KEY FINDER_SECRET_KEY FINDER_SESSION_TOKEN <<< "$finder_creds"

echo Assumed 3

# Get writer credentials
echo "Getting writer credentials..."
writer_creds=$(aws sts get-session-token \
    --duration-seconds 3600 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)

IFS=$'\t' read -r WRITER_ACCESS_KEY WRITER_SECRET_KEY WRITER_SESSION_TOKEN <<< "$writer_creds"

# Generate JSON payload
cat << EOF > "$(dirname "$0")/env/payload.json"
{
    "FINDER_ACCESS_KEY": "$FINDER_ACCESS_KEY",
    "FINDER_SECRET_KEY": "$FINDER_SECRET_KEY",
    "FINDER_SESSION_TOKEN": "$FINDER_SESSION_TOKEN",
    "WRITER_ACCESS_KEY": "$WRITER_ACCESS_KEY",
    "WRITER_SECRET_KEY": "$WRITER_SECRET_KEY",
    "WRITER_SESSION_TOKEN": "$WRITER_SESSION_TOKEN",
    "ACCOUNTS": "$ACCOUNTS",
    "EXTERNAL_ID": "$EXTERNAL_ID"
}
EOF
echo Created env/payload.json with the temporary credentials to run the Lambda
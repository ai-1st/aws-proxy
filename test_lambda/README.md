This is a test lambda that scans all RDS instances in the given accounts and regions of an AWS Organization.

When it starts, it uses the temporary credentials that are provided in the payload to assume roles in the target accounts.
The names of the roles to assume are passed as lambda parameters.

The lambda uses rds.describe_db_instances to get a list of RDS databases.

For each database, it gets 7-day p99 statistics for WriteIOPS, WriteThroughput, ReadIOPS, ReadThroughput, CPUUtilization, DatabaseConnections metrics from CloudWatch for the trailing 12 weeks.

It then exports the results to a CSV file using the temporary credentials provided in the payload.

The lambda is deployed using AWS SAM. The template has the following parameters:

- ROLE_NAME: The name of the role to assume in the target accounts
- OUTPUT: The S3 path to the output CSV file
- SUBNET_ID: The ID of the subnet to use for the lambda
- SECURITY_GROUP_ID: The ID of the security group to use for the lambda
- HTTP_PROXY: The HTTP proxy to use for the lambda
- AWS_CA_BUNDLE: The path to the CA bundle to use for the lambda, default is /opt/aws-proxy.crt

The Lambda payload should contain the following parameters:
- FINDER_ACCESS_KEY
- FINDER_SECRET_KEY
- FINDER_SESSION_TOKEN
- WRITER_ACCESS_KEY
- WRITER_SECRET_KEY
- WRITER_SESSION_TOKEN

There is a helper bash script that generates the payload parameters by assuming roles in the finder account and writer account.

The script is called `generate_payload.sh` and is located in the `test_lambda` directory. The script requires the following environment variables 
which are defined in .env.sh not under source control:

- FINDER_ROLE_ARN
- FINDER_ROLE2_ARN
- WRITER_ROLE_ARN






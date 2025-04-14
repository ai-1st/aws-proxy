This is a test lambda that scans all RDS instances in the given accounts and regions of an AWS Organization.

When it starts, it assumes an intermediary role, and then assumes roles in the target accounts.
The names of the roles to assume are passed as lambda parameters.

The lambda uses rds.describe_db_instances to get a list of RDS databases.

For each database, it gets 7-day p99 statistics for WriteIOPS, WriteThroughput, ReadIOPS, ReadThroughput, CPUUtilization, DatabaseConnections metrics from CloudWatch for the trailing 12 weeks.

It then exports the results to a CSV file.

The lambda is deployed using AWS SAM. The template has the following parameters:

- ROLE1: The name of the role to assume in the current account
- ROLE2: The name of the role to assume in the target account
- OUTPUT: The S3 path to the output CSV file
- SUBNET_ID: The ID of the subnet to use for the lambda
- SECURITY_GROUP_ID: The ID of the security group to use for the lambda
- HTTP_PROXY: The HTTP proxy to use for the lambda
- AWS_CA_BUNDLE: The path to the CA bundle to use for the lambda, default is /opt/aws-proxy.crt







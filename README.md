# infra-rds
RDS databases

Creating Aurora clusters global and regional.

Examples
first run infra-dev-dbc
ENV=infra-dev-dbc AWS_PROFILE=infra-dev AWS_DEFAULT_REGION=us-east-1 cdk --profile infra-dev diff

Make a new login to a secondary region 
and run infra-dev-dbc-secondary
ENV=infra-dev-dbc-secondary AWS_PROFILE=infra-dev-ohio AWS_DEFAULT_REGION=us-east-2 cdk --profile infra-dev-ohio diff

There is a branch named "bootstrap_together" for one run all together. Delete it.

Now, CDK can not create a secondary cluster with serverless_v2 class.


Fro PROD environment increase min and max ACU resources.

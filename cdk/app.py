#!/usr/bin/env python3
from aws_cdk import (
    App,
    Aspects,
    Tags
)

from lib.resources.aspect_checker import AspectChecker
# from aws_cdk import core
from lib.application import ApplicationStack
import os
import sys
import json
import boto3
from lib.resources.aspect_checker import AspectChecker
from lib.common import Common as _common

#
# Pre-Initialization
#
sys.path.append('/plum/infra-rds/cdk/lib')

#
# Opening JSON properties file
#
with open('properties.' + os.environ["ENV"] + '.json', "r") as env_file:
    env_data = json.load(env_file)

env_data['environment'] = os.environ["ENV"] if '.' not in os.environ["ENV"] else os.environ["ENV"].split('.')[1]

common = _common(env_name=env_data['environment'], app_name=env_data['app_name'])

#
# Set our application name using the app_name and environment name from our properties file
#
env_data['app_name'] = f"{env_data['app_name']}{env_data['environment'].capitalize()}"

#
# Grab our organization Id from AWS to be used later
#
try:
    _org = boto3.client("organizations")
    _aws_request = _org.describe_organization()

    _my_org = _aws_request['Organization']['Id']

    env_data['principal_org_id'] = _my_org
    print(f"Setting Organization Id to: {env_data['principal_org_id']}")

    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    print(f"Setting Account ID to: {account_id}")
except Exception as e:
    if 'expired' in str(e):
        print(str(e))
        print("ERROR: FAILING BECAUSE YOUR CREDENTIALS HAVE EXPIRED OR YOU DIDNT PASS IN AWS_PROFILE")
        sys.exit(1)

    print("ERROR: Unknown error. Could not retrieve the org id. " + str(e))

# Print environment
# for key, value in env_data.items():
#     print(f"{key}: {value}")
# for key, value in os.environ.items():
#     print(f"{key}: {value}")

app = App()
application = ApplicationStack(
    app,
    id=env_data['app_name'],
    vpc=env_data['vpc_name'],
    env={
        'region': os.environ['CDK_DEFAULT_REGION'],
        'account': os.environ['CDK_DEFAULT_ACCOUNT']
    },
    env_context=env_data
)

# Apply your Aspects and Tags as before
Aspects.of(application).add(AspectChecker(
    env_name=env_data['app_name'],
    env={
        'region': os.environ['CDK_DEFAULT_REGION'],
        'account': os.environ['CDK_DEFAULT_ACCOUNT']
    }
))
Tags.of(application).add("stack_type", "CDK")
Tags.of(application).add("stack_name", application.stack_name)
Tags.of(application).add("env_name", application.env_name)

app.synth()

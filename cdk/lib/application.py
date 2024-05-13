from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    Duration,
    RemovalPolicy
)
from constructs import Construct

import os
import json
from lib.lambda_as_stack import DBUsersLambda as _lambda
from lib.common import Common as _common


class ApplicationStack(Stack):

    def __init__(self, scope: Construct, id: str, vpc: str, **kwargs) -> None:
        env_context = kwargs.pop('env_context')

        # region = os.environ['CDK_DEFAULT_REGION']

        super().__init__(scope, id, **kwargs)

        if not env_context:
            return

        self.env_data = env_context
        self.env_name = self.env_data['environment']

        #
        # Now set all of our other variables from the env_data pulled from the environment file.
        #
        self.app_name = id
        self.vpc_name = vpc
        self.mgmt_vpc_name = self.env_data['mgmt_vpc_name']
        common = _common(env_name=env_context['environment'], app_name=self.app_name)
        self.db_user_list = self.env_data['create_db_users']

        removal_policy_mapping = {
            'DESTROY': RemovalPolicy.DESTROY,
            'RETAIN': RemovalPolicy.RETAIN,
            'SNAPSHOT': RemovalPolicy.SNAPSHOT
        }
        # Ensure the policy is valid
        if self.env_data['removal_policy'].upper() not in removal_policy_mapping:
            raise ValueError(
                f"Invalid removal policy: {self.env_data['removal_policy']}. Must be one of: {', '.join(removal_policy_mapping.keys())}")

        # Map string to RemovalPolicy
        self.removal_policy = removal_policy_mapping[self.env_data['removal_policy'].upper()]

        #
        # Replace __REGION__ in all locations from our properties file
        #
        new_env_data = json.dumps(self.env_data).replace('__REGION__', self.region)
        self.env_data = json.loads(new_env_data)

        #
        # Find our vpc and use it to build the resources.
        #
        self.vpc = ec2.Vpc.from_lookup(
            self,
            # id='vpc',
            id=f'vpc',
            vpc_name=self.vpc_name,
            is_default=False
        )

        # Generate lambda stack
        self.userlambda = _lambda(
            self,
            id=f"user_db_lambda",
            stack_name=f"{self.app_name}-TempLambda",
            env={
                'region': os.environ['CDK_DEFAULT_REGION'],
                'account': os.environ['CDK_DEFAULT_ACCOUNT']
            },
            env_context=self)

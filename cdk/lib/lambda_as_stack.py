from aws_cdk import (
    Stack,
    CfnOutput,
    Duration,
    aws_iam as iam,
    aws_lambda as dblambda,
    aws_ec2 as ec2,
    aws_ssm as ssm,
    aws_secretsmanager as secretsmanager,
    aws_logs as _logs,
    aws_kms as kms,
    aws_iam as _iam,
    custom_resources as _cr,
)
from constructs import Construct
import json
import base64


class DBUsersLambda(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        env_context = kwargs.pop('env_context')

        super().__init__(scope, id, **kwargs)

        if not env_context:
            return

        self.db_stack_name = "rdsDevdbc"  # TODO properties
        self.db_user_list = env_context.db_user_list

        # Import our KMS key
        #
        self.kms_key_arn = ssm.StringParameter.from_string_parameter_name(
            self,
            id="kms_key_arn",
            string_parameter_name=f"/infra/{self.db_stack_name}/kms/key_arn")

        self.kms_key = kms.Key.from_key_arn(
            self,
            id='kms_key',
            key_arn=self.kms_key_arn.string_value)

        self.rds_admin_credentials_secret = secretsmanager.Secret.from_secret_name_v2(
            self,
            'RSAKeyForEC2Sanitize',
            f"/infra/{self.db_stack_name}/rds/credential"
        )

        self.secret_db_admin_login_arn = self.rds_admin_credentials_secret.secret_arn

        # Define the Lambda function
        self.create_db_users_lambda = dblambda.Function(
            scope,
            f"db-password-generation-lambda",
            runtime=dblambda.Runtime.PYTHON_3_10,
            handler="create_passwords.lambda_handler",
            log_retention=_logs.RetentionDays.ONE_MONTH if 'prod' not in env_context.env_data[
                'environment'] else _logs.RetentionDays.ONE_YEAR,

            code=dblambda.Code.from_asset("lib/functions/db_passwords"),
            timeout=Duration.seconds(300),
            retry_attempts=0,
            vpc=env_context.vpc,
            current_version_options=dblambda.VersionOptions(
                removal_policy=env_context.removal_policy,
                retry_attempts=1
            ),
            environment={
                'ADMIN_DB_PASSWORD_SECRET_ARN': self.secret_db_admin_login_arn  # TODO also as a payload parameter ?
                # 'USER_LIST': base64_str
                # 'KMS_KEY_ID': kms_key_id.value_as_string
            }
        )

        # Define the security group
        lambda_sg = ec2.SecurityGroup(
            scope,
            "LambdaSecurityGroup",
            vpc=env_context.vpc,
            description="Security group for Lambda function",
            allow_all_outbound=False
        )

        # Add outbound rules
        lambda_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic"
        )
        lambda_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic"
        )

        # Add inbound rule for all traffic from VPC
        lambda_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(env_context.vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic(),
            description="Allow all inbound traffic from VPC"
        )

        # Allow the Lambda function to connect to resources within the VPC
        self.create_db_users_lambda.connections.allow_from(
            lambda_sg,
            ec2.Port.all_traffic(),
            "Allow Lambda to access resources within VPC"
        )

        rds_sg_id_parameter = f"/infra/{self.db_stack_name}/rds/sg_id"

        # Retrieve the RDS security group ID from the Parameter Store
        rds_sg_id_ssm_parameter = ssm.StringParameter.from_string_parameter_name(
            scope,
            "GetRdsSecurityGroupId",
            string_parameter_name=rds_sg_id_parameter
        )

        # Retrieve the security group ID value
        rds_sg_id = rds_sg_id_ssm_parameter.string_value

        # Create a reference to the existing RDS security group using the retrieved ID
        rds_sg = ec2.SecurityGroup.from_security_group_id(
            scope,
            "ExistingRdsSecurityGroup",
            security_group_id=rds_sg_id
        )

        # Add an ingress rule to the existing RDS security group allowing traffic from the Lambda security group
        rds_sg.add_ingress_rule(
            peer=lambda_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from Lambda security group"
        )
        # self.create_db_users_lambda.node.add_dependency(rds_sg)
        # TODO  @jsii/kernel.RuntimeError: Error: 'rdsDevdbc/user_db_lambda' depends on 'rdsDevdbc'
        #  (rdsDevdbc/user_db_lambda -> rdsDevdbc/db-password-generation-lambda/Resource.Arn).
        #  Adding this dependency (rdsDevdbc -> rdsDevdbc/user_db_lambda/rdsDevdbcdbc2_db_credentials/Resource.Ref)
        #  would create a cyclic reference.
        # add_lambda_security_group_to_rds_security_group(scope, sg, rds_sg_id_parameter)

        self.create_db_users_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["*"],
            resources=["*"],
            effect=iam.Effect.ALLOW
        ))
        # "ec2:RunInstances",
        # "ec2:CreateTags",

        self.lambda_layer = dblambda.LayerVersion(
            scope,
            id="lambda_layer",
            removal_policy=env_context.removal_policy,
            code=dblambda.Code.from_asset('lib/functions/lambda_layers/db_passwords'),
            compatible_architectures=[dblambda.Architecture.X86_64]
        )
        self.create_db_users_lambda.add_layers(self.lambda_layer)

        # # Example of adding an environment variable to the Lambda function
        # my_lambda.add_environment("MY_ENV_VARIABLE", "my_value")

        # Example of granting permissions to the Lambda function (e.g., to access other AWS resources)
        # my_lambda.add_to_role_policy(...)

        #
        # Stack outputs are here.
        #
        CfnOutput(self, "user_lambda_arn", value=self.create_db_users_lambda.function_arn)

        # Prepare the custom resource policy statement
        policy_statement = _iam.PolicyStatement(
            actions=[
                "lambda:InvokeFunction"
            ],
            effect=_iam.Effect.ALLOW,
            resources=[self.create_db_users_lambda.function_arn]
        )

        # Create a list to hold custom resource instances
        custom_resources = []

        # Iterate through each user in db_user_list
        for user in self.db_user_list:
            # Convert user dictionary to JSON
            user_json = json.dumps(user)
            bytes_data = user_json.encode('utf-8')

            # Encode data to Base64
            base64_str = base64.b64encode(bytes_data).decode('utf-8')

            # Create an AWS Custom Resource for each user
            custom_resource = _cr.AwsCustomResource(
                self,
                id=f'invoke_lambda_{user["user_name"]}',
                policy=_cr.AwsCustomResourcePolicy.from_statements(
                    statements=[policy_statement]
                ),
                timeout=Duration.minutes(5),
                on_create=_cr.AwsSdkCall(
                    service="Lambda",
                    action="invoke",
                    parameters={
                        "FunctionName": self.create_db_users_lambda.function_arn,
                        "InvocationType": "RequestResponse",
                        "Payload": json.dumps({"User": base64_str})
                    },
                    physical_resource_id=_cr.PhysicalResourceId.of(f'invoke_lambda_{user["user_name"]}')
                ),
                on_update=_cr.AwsSdkCall(
                    service="Lambda",
                    action="invoke",
                    parameters={
                        "FunctionName": self.create_db_users_lambda.function_arn,
                        "InvocationType": "RequestResponse",
                        "Payload": json.dumps({"User": base64_str})

                    },
                    physical_resource_id=_cr.PhysicalResourceId.of(f'invoke_lambda_{user["user_name"]}_update')
                    # install_latest_aws_sdk=False
                )
            )

            # Add the custom resource to the list
            custom_resources.append(custom_resource)

            # custom_resource.node.add_dependency(lambda_arn) # TODO why error: Passed to parameter deps of method constructs.Node#addDependency: Unable to deserialize value as constructs.IDependable

            # Store the list of custom resources as part of the stack (optional)
            self.custom_resources = custom_resources

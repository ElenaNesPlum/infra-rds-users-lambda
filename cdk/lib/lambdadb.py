from aws_cdk import (
    RemovalPolicy,
    Duration,
    CfnOutput,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_ec2 as ec2,
    aws_ssm as ssm,
    aws_cloudformation as cfn,
    aws_logs as _logs
)

import time
import boto3

# Add Lambda security group to existing RDS security group
# def add_lambda_security_group_to_rds_security_group(scope, lambda_sg, rds_sg_id_parameter_name):
#
#     # Retrieve the RDS security group ID from the Parameter Store
#     rds_sg_id_ssm_parameter = ssm.StringParameter.from_string_parameter_name(
#         scope,
#         "RdsSecurityGroupId",
#         string_parameter_name=rds_sg_id_parameter_name
#     )
#
#     # Retrieve the security group ID value
#     rds_sg_id = rds_sg_id_ssm_parameter.string_value
#
#     # Create a reference to the existing RDS security group using the retrieved ID
#     rds_sg = ec2.SecurityGroup.from_security_group_id(
#         scope,
#         "ExistingRdsSecurityGroup",
#         security_group_id=rds_sg_id
#     )
#
#     # Add an ingress rule to the existing RDS security group allowing traffic from the Lambda security group
#     rds_sg.add_ingress_rule(
#         peer=lambda_sg,
#         connection=ec2.Port.all_traffic(),
#         description="Allow all traffic from Lambda security group"
#     )

def check_rds_cluster_status(cluster_identifier):
    client = boto3.client('rds')
    while True:
        response = client.describe_db_clusters(DBClusterIdentifier=cluster_identifier)
        cluster = response['DBClusters'][0]  # Assuming only one cluster

        # Check the status of the RDS cluster
        status = cluster['Status']
        print(f"RDS cluster status: {status}")

        # Check if the RDS cluster is available
        if status == 'available':
            print("RDS cluster is available!")
            break  # Exit the polling loop

        # Wait before checking again
        time.sleep(10)

def create_lambda(scope, vpc, admin_rds_secret_name_arn, stack_name, removal_policy):
    """
    Create a Lambda function within an existing stack.

    Parameters:
    - scope: The scope within which the Lambda function is being created.
    - vpc: The VPC within which the Lambda function will operate.
    - admin_rds_secret_name_arn: The ARN of the secret containing the admin RDS credentials.
    - stack_name: The name of the CloudFormation stack to work within.
    - removal_policy: The removal policy for the Lambda function (e.g., RETAIN, DESTROY).
    - db_user_list: A list of database users for which the Lambda function will create passwords.

    Returns:
    - The ARN of the created Lambda function.
    """

    # # Convert the list to JSON string
    # json_str = json.dumps(db_user_list)
    #
    # # Convert string to bytes
    # bytes_data = json_str.encode('utf-8')
    #
    # # Encode bytes data to Base64
    # base64_str = base64.b64encode(bytes_data).decode('utf-8')

    # Define the Lambda function
    create_db_users_lambda = _lambda.Function(
        scope,
        f"db-password-generation-lambda",
        runtime=_lambda.Runtime.PYTHON_3_10,
        handler="create_passwords.lambda_handler",
        # log_retention=_logs.RetentionDays.ONE_MONTH if 'prod' not in env_context.env_data[  # TODO
        #    'environment'] else _logs.RetentionDays.ONE_YEAR,

        code=_lambda.Code.from_asset("lib/functions/db_passwords"),
        timeout=Duration.seconds(300),
        retry_attempts=0,
        vpc=vpc,
        current_version_options=_lambda.VersionOptions(
            removal_policy=removal_policy,
            retry_attempts=1
        ),
        environment={
            'ADMIN_DB_PASSWORD_SECRET_ARN': admin_rds_secret_name_arn  # TODO also as a payload parameter ?
        }
    )

    # create_db_users_lambda.node.add_dependency(scope.primary_cluster)
    CfnOutput(scope, "Lambda successfully created", value="")

    # Define the security group
    lambda_sg = ec2.SecurityGroup(
        scope,
        "LambdaSecurityGroup",
        vpc=vpc,
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
        peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
        connection=ec2.Port.all_traffic(),
        description="Allow all inbound traffic from VPC"
    )

    # Allow the Lambda function to connect to resources within the VPC
    create_db_users_lambda.connections.allow_from(
        lambda_sg,
        ec2.Port.all_traffic(),
        "Allow Lambda to access resources within VPC"
    )

    rds_sg_id_parameter = f"/infra/{stack_name}/rds/sg_id"

    # Retrieve the RDS security group ID from the Parameter Store
    rds_sg_id_ssm_parameter = ssm.StringParameter.from_string_parameter_name(
        scope,
        "RdsSecurityGroupId",
        string_parameter_name=rds_sg_id_parameter
    )

    # Attempt to retrieve the existing parameter
    rds_sg_id_ssm_parameter = ssm.StringParameter.from_string_parameter_name(
        scope,
        "GetRdsSecurityGroupId",
        string_parameter_name=rds_sg_id_parameter
    )
    CfnOutput(scope, "Parameter exists rds_sg_id_output ", value=rds_sg_id_ssm_parameter.string_value)

    if not rds_sg_id_ssm_parameter:
        # If the parameter does not exist
        rds_sg_id_ssm_parameter = ssm.StringParameter(
            scope,
            id='rds-sg-ssm-from-lambda',
            string_value="place holder",
            parameter_name=rds_sg_id_parameter,
            overwrite=False  # Do not overwrite
        )

    # Retrieve the security group ID value
    rds_sg_id = rds_sg_id_ssm_parameter.string_value
    CfnOutput(scope, "RDS SG found ID= ", value=rds_sg_id)

    # Create a reference to the existing RDS security group using the retrieved ID
    rds_sg = ec2.SecurityGroup.from_security_group_id(
        scope,
        "ExistingRdsSecurityGroup",
        security_group_id=rds_sg_id
    )
    # create_db_users_lambda.node.add_dependency(rds_sg)

    # Add an ingress rule to the existing RDS security group allowing traffic from the Lambda security group
    rds_sg.add_ingress_rule(
        peer=lambda_sg,
        connection=ec2.Port.all_traffic(),
        description="Allow all traffic from Lambda security group"
    )
    CfnOutput(scope, "Add an ingress rule to the existing RDS SG", value="")
    # create_db_users_lambda.node.add_dependency(rds_sg)

    # add_lambda_security_group_to_rds_security_group(scope, sg, rds_sg_id_parameter)

    create_db_users_lambda.add_to_role_policy(iam.PolicyStatement(
        actions=["*"],
        resources=["*"],
        effect=iam.Effect.ALLOW
    ))
    # "ec2:RunInstances",
    # "ec2:CreateTags",

    lambda_layer = _lambda.LayerVersion(
        scope,
        id="lambda_layer",
        removal_policy=removal_policy,
        code=_lambda.Code.from_asset('lib/functions/lambda_layers/db_passwords'),
        compatible_architectures=[_lambda.Architecture.X86_64]
    )
    create_db_users_lambda.add_layers(lambda_layer)

    # # Example of adding an environment variable to the Lambda function
    # my_lambda.add_environment("MY_ENV_VARIABLE", "my_value")

    # Example of granting permissions to the Lambda function (e.g., to access other AWS resources)
    # my_lambda.add_to_role_policy(...)

    return create_db_users_lambda.function_arn

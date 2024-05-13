import os
import json
import boto3
import botocore
import jsii
from aws_cdk import (
    IAspect,
    Annotations,
    aws_autoscaling as _autoscaling,
    aws_ec2 as _ec2
)
from constructs import IConstruct


class ASGProps():
    def __init__(self,
                 name=None,
                 min_size=None,
                 max_size=None,
                 desired_capacity=None):
        self.name = name
        self.min_size = min_size
        self.max_size = max_size
        self.desired_capacity = desired_capacity


@jsii.implements(IAspect)
class AspectChecker():
    def format_message(self, msg):
        formatted = '\n'.join((
            ' ',
            '************************************************************',
            '*** AspectChecker(): ' + msg,
            '************************************************************'
        ))
        return formatted

    def launchconfig_checker(self, node):
        if isinstance(node, _autoscaling.CfnLaunchConfiguration) or isinstance(node, _ec2.CfnInstance):
            if not node.ebs_optimized:
                if 't2' not in node.instance_type:
                    annotations = Annotations.of(node)
                    # node.node.add_warning(self.format_message(msg='EbsOptimized is set to False, but instance type ('+node.instance_type+') is capable. Setting EbsOptimized to True.'))
                    annotations.add_warning(self.format_message(
                        msg='EbsOptimized is set to False, but instance type (' + node.instance_type + ') is capable. Setting EbsOptimized to True.'))
                    node.add_override("Properties.EbsOptimized", True)

    def autoscaling_checker(self, node):
        if isinstance(node, _autoscaling.CfnAutoScalingGroup):
            # Test for update policy options, if it exists...
            update_policy_options = node.cfn_options
            if not update_policy_options.update_policy.auto_scaling_scheduled_action.ignore_unmodified_group_size_properties:
                node.node.add_warning(
                    self.format_message(
                        msg='WARNNG: Setting ASG UpdatePolicy to include IgnoreUnmodifiedGroupSizeProperties.\n'
                            + '*** AFTER This is set. Use ASG and Pipelines to Change min_size, max_size, desired_capacity and leave the CDK alone!'))

            node.add_override("UpdatePolicy.AutoScalingScheduledAction.IgnoreUnmodifiedGroupSizeProperties", True)

    def visit(self, node: IConstruct) -> None:
        self.launchconfig_checker(node=node)
        self.autoscaling_checker(node=node)

    def _finditems(self, obj, value, level=None):
        for k, v in obj.items():
            if isinstance(v, dict):
                item = self._finditems(v, value, k if level is None else ','.join((level, k)))
                if item is not None:
                    return item
            elif v == value:
                self.asg_names.append(','.join((level, k, v)))
        return

    def __init__(self, env_name=None, env=None):

        if env_name is None:
            raise Exception("env_name is None")
            return

        self.asg_names = list()

        self.asgs = {}
        self.asgProps = {}

        self.env_name = env_name
        self.env = env
        self.env_file_name = 'cdk.out/' + self.env_name + '.template.json'

        try:
            self.env_file = open(self.env_file_name, "r")
            self.tree = json.load(self.env_file)
            self.env_file.close
        except Exception as e:
            self.tree = e

    def get_autoscale_groups(self, node):
        if not self.tree or isinstance(self.tree, Exception):
            node.node.add_warning("******** self.tree empty or is an Exception ********")
            return False

        self._finditems(self.tree, "AWS::AutoScaling::AutoScalingGroup")

        for asg_name in self.asg_names:
            flist = asg_name.split(',')

            try:
                autoscale_client = boto3.client('autoscaling', region_name=self.env['region'])
                response = autoscale_client.describe_auto_scaling_groups()
                # node.node.add_warning("******** boto response: ********\n" + str(response))

                all_asg = response['AutoScalingGroups']
                for asg in all_asg:
                    if flist[1] in asg['AutoScalingGroupName']:
                        n = self.tree['Resources'][flist[1]]['Metadata']['aws:cdk:path']
                        self.asgProps[n] = ASGProps(
                            name=self.tree['Resources'][flist[1]]['Metadata']['aws:cdk:path'],
                            min_size=asg['MinSize'],
                            max_size=asg['MaxSize'],
                            desired_capacity=asg['DesiredCapacity']
                        )
            except botocore.exceptions.ClientError as error:
                node.node.add_warning("******** botocore.exceptions.ClientError ********")
                raise error
            except botocore.exceptions.ParamValidationError as error:
                raise ValueError('The parameters you provided are incorrect: {}'.format(error))
            except Exception as error:
                node.node.add_warning("******** Some OTHER exception occurred with Boto. ********")
                raise error

        return self.asgProps

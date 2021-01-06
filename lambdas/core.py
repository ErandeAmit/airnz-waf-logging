import boto3, datetime, os, time, json, yaml
from cfn_flip import flip, to_yaml, to_json


sqs = boto3.client('sqs')
sqsqueue = os.environ['SLACK_NOTIFICATIONS_SQS_QUEUE']
slack_user = os.environ['SLACK_USERNAME']
template_bucket = '337196071970-cfn-templates'
template_key_roles = 'prod-firehose-waf-logs-stacksets/stackset-roles.yml'
template_url_roles = f"https://{template_bucket}.s3-ap-southeast-2.amazonaws.com/{template_key_roles}"
template_key_regional = 'prod-firehose-waf-logs-stacksets/stackset-regional.yml'
template_url_regional = f"https://{template_bucket}.s3-ap-southeast-2.amazonaws.com/{template_key_regional}"
stackset_description = 'Resources for Kinesis Firehose delivery stream for central WAF logging'
stackset_description_regional = 'Resources for Kinesis Firehose delivery stream for central WAF logging - Regional'

parameters=[
                {
                'ParameterKey': 'FirehoseIAMRoleName',
                'ParameterValue': os.environ['STACK_SET_FIREHOSE_IAM_ROLE_NAME']
                },
                {
                'ParameterKey': 'LogGroup',
                'ParameterValue': os.environ['STACK_SET_LOG_GROUP']
                },
                {
                'ParameterKey': 'LogStream',
                'ParameterValue': os.environ['STACK_SET_LOG_STREAM']
                }
            ]

def paginate(method, **kwargs):
    client = method.__self__
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result

def send_to_slack(message):
    return sqs.send_message(
        QueueUrl=sqsqueue,
        MessageBody="""
            {
            "Channel": "botcheck",
            "Username": "%s",
            "Message": "%s"
            }
            """
            % (slack_user,message)
        )

def lambda_handler(event, context):

    session = boto3.Session()
    dynamodb = session.resource('dynamodb')
    ec2 = boto3.client('ec2')
    acctable = dynamodb.Table(os.environ['ACC_TABLE_NAME'])
    cfn = boto3.client('cloudformation')
    timenow = (str(datetime.datetime.now()).split('.')[0]).replace(" ","-").replace(":","-")
    stacksetname_roles = os.environ['STACK_SET_NAME_ROLES']
    stacksetname_regional = os.environ['STACK_SET_NAME_REGIONAL']
    adminrolearn = os.environ['ADMIN_ROLE_ARN']
    executionrolename = os.environ['EXECUTION_ROLE_NAME']


    Tags =  [
            { "Key": "airnz:bus:owner", "Value": "AWS Platform Management" },
            { "Key": "airnz:bus:product", "Value": "Firehose for WAF logs" },
            { "Key": "airnz:bus:severity", "Value": "Severity3" },
            { "Key": "airnz:sec:classification", "Value": "Sensitive" },
            { "Key": "airnz:sec:domain", "Value": "High" },
            { "Key": "airnz:tech:name", "Value": "firehose-waf-logs" },
            { "Key": "airnz:tech:environment", "Value": "prod" }
        ]


    ### Roles
    wait_timer_next_deployment = 1
    to_create_stack_set = False
    try:
        descresp = cfn.describe_stack_set(StackSetName=stacksetname_roles)
        send_to_slack("StackSet: <%s|%s>" % ("https://ap-southeast-2.console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stackset/detail?stackSetId=" + stacksetname_roles, stacksetname_roles))
    except Exception as e:
        print(e)
        if 'not found' in str(e):
            to_create_stack_set = True

    accresp = acctable.scan()
    stackset_principals = []

    for i in accresp['Items']:
        stackset_principals.append(i['AWSAccountID'])

    if to_create_stack_set is True:
        response = cfn.create_stack_set(
            StackSetName=stacksetname_roles,
            Description=stackset_description,
            TemplateURL=template_url_roles,
            Parameters=parameters,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=Tags,
            AdministrationRoleARN=adminrolearn,
            ExecutionRoleName=executionrolename,
        )
        response = cfn.create_stack_instances(
            StackSetName=stacksetname_roles,
            Accounts=stackset_principals,
            OperationPreferences={
                'FailureToleranceCount': 99,
                'MaxConcurrentCount': 100
            },
            Regions=[
                'ap-southeast-2',
            ]
        )
        wait_timer_next_deployment = 60
        send_to_slack("StackSet created: <%s|%s>" % (f"https://ap-southeast-2.console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacksets/{stacksetname_roles}/info", stacksetname_roles))

    else:
        # Add missing stack instances (stack instances = AWS accounts)
        current_principals = []
        response = cfn.list_stack_instances(
            StackSetName=stacksetname_roles
            )

        for i in response['Summaries']:
            current_principals.append(i['Account'])
        diff_principals = set(stackset_principals) - set(current_principals)
        if diff_principals:
            diff_alias = []
            for p in diff_principals:
                diff_alias.append([j['AWSAccountAlias'] for j in accresp['Items'] if p == j['AWSAccountID']][0])
            print(sorted(diff_alias))
            send_to_slack('Adding missing principals to StackSet instances: %s' % "\n>".join(sorted(diff_alias)))
            response = cfn.create_stack_instances(
                StackSetName=stacksetname_roles,
                Accounts=list(diff_principals),
                Regions=[
                    'ap-southeast-2',
                    ]
                )
            wait_timer_next_deployment = 30
        else:
            send_to_slack('(Roles deployment) No change to StackSet instance principals')

        # Update template if there are missing or removed CFN exports
        s3 = boto3.resource('s3')
        obj = s3.Object(template_bucket, template_key_roles)
        body = obj.get()['Body'].read()
        if flip(body) == flip(descresp['StackSet']['TemplateBody']):
            send_to_slack('(Roles deployment) No change to StackSet CFN template')
        else:
            send_to_slack('(Roles deployment) Change detected in StackSet CFN template, updating StackSet')
            response = cfn.list_stack_set_operations(
                StackSetName=stacksetname_roles
                )
            operation_pending = False
            for i in response['Summaries']:
                if i['Status'] == 'RUNNING':
                    operation_pending = True
            while operation_pending == True:
                send_to_slack('Another StackSet operation is in progress, waiting 10 seconds before retrying')
                time.sleep(10)
                response = cfn.list_stack_set_operations(
                    StackSetName=stacksetname_roles
                    )
                operation_pending = False
                for i in response['Summaries']:
                    if i['Status'] == 'RUNNING':
                        operation_pending = True
            response = cfn.update_stack_set(
                StackSetName=stacksetname_roles,
                TemplateURL=template_url_roles,
                Parameters=parameters,
                OperationPreferences={
                    'FailureToleranceCount': 99,
                    'MaxConcurrentCount': 100
                },
                Description=stackset_description,
                AdministrationRoleARN=adminrolearn,
                ExecutionRoleName=executionrolename,
                Capabilities=['CAPABILITY_NAMED_IAM']
                )
            wait_timer_next_deployment = 30




    ### Regional
    time.sleep(wait_timer_next_deployment)
    to_create_stack_set = False
    try:
        descresp = cfn.describe_stack_set(StackSetName=stacksetname_regional)
        send_to_slack("StackSet: <%s|%s>" % ("https://ap-southeast-2.console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stackset/detail?stackSetId=" + stacksetname_regional, stacksetname_regional))
    except Exception as e:
        print(e)
        if 'not found' in str(e):
            to_create_stack_set = True

    if to_create_stack_set is True:
        response = cfn.create_stack_set(
            StackSetName=stacksetname_regional,
            Description=stackset_description_regional,
            Parameters=parameters,
            TemplateURL=template_url_regional,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=Tags,
            AdministrationRoleARN=adminrolearn,
            ExecutionRoleName=executionrolename,
        )
        response = cfn.create_stack_instances(
            StackSetName=stacksetname_regional,
            Accounts=stackset_principals,
            OperationPreferences={
                'FailureToleranceCount': 99,
                'MaxConcurrentCount': 100
            },
            Regions=[
                'ap-southeast-2',
                'us-east-1'
            ]
        )

        send_to_slack("StackSet created: <%s|%s>" % (f"https://ap-southeast-2.console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacksets/{stacksetname_regional}/info", stacksetname_regional))

    else:
        # Add missing stack instances (stack instances = AWS accounts)
        stackset_principals = []
        current_principals = []
        response = cfn.list_stack_instances(
            StackSetName=stacksetname_regional
            )

        for i in response['Summaries']:
            current_principals.append(i['Account'])
        diff_principals = set(stackset_principals) - set(current_principals)
        if diff_principals:
            diff_alias = []
            for p in diff_principals:
                diff_alias.append([j['AWSAccountAlias'] for j in accresp['Items'] if p == j['AWSAccountID']][0])
            print(sorted(diff_alias))
            send_to_slack('Adding missing principals to StackSet instances: %s' % "\n>".join(sorted(diff_alias)))
            response = cfn.create_stack_instances(
                StackSetName=stacksetname_regional,
                Accounts=list(diff_principals),
                Regions=[
                    'ap-southeast-2',
                    'us-east-1'
                    ]
                )
        else:
            send_to_slack('(Regional deployment) No change to StackSet instance principals')

        # Update template if there are missing or removed CFN exports
        s3 = boto3.resource('s3')
        obj = s3.Object(template_bucket, template_key_regional)
        body = obj.get()['Body'].read()
        if flip(body) == flip(descresp['StackSet']['TemplateBody']):
            send_to_slack('(Regional deployment) No change to StackSet CFN template')
        else:
            send_to_slack('(Regional deployment) Change detected in StackSet CFN template, updating StackSet')
            response = cfn.list_stack_set_operations(
                StackSetName=stacksetname_regional
                )
            operation_pending = False
            for i in response['Summaries']:
                if i['Status'] == 'RUNNING':
                    operation_pending = True
            while operation_pending == True:
                send_to_slack('Another StackSet operation is in progress, waiting 10 seconds before retrying')
                time.sleep(10)
                response = cfn.list_stack_set_operations(
                    StackSetName=stacksetname_regional
                    )
                operation_pending = False
                for i in response['Summaries']:
                    if i['Status'] == 'RUNNING':
                        operation_pending = True
            response = cfn.update_stack_set(
                StackSetName=stacksetname_regional,
                TemplateURL=template_url_regional,
                Parameters=parameters,
                OperationPreferences={
                    'FailureToleranceCount': 99,
                    'MaxConcurrentCount': 100
                },
                Description=stackset_description,
                AdministrationRoleARN=adminrolearn,
                ExecutionRoleName=executionrolename,
                Capabilities=['CAPABILITY_NAMED_IAM']
                )

    return event

'''
Brute functions for WeirdAAL

This is the main brute library so that we can get an idea what services a particular
key has access to. We do this by asking if we have permission on as many services &
subfunctions as we can. Printed to screen and logged to db.
'''

import boto3
import botocore
import datetime
import json
import logging
import os
import pprint
import sys


from libs.aws.sql import *

pp = pprint.PrettyPrinter(indent=5, width=80)

logging.basicConfig(level=logging.ERROR, format='%(message)s', filename='target.txt', filemode='w')


# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

region = 'us-east-1'

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def get_accountid():
    '''
    Get the accountID via sts call
    '''
    try:
        client = boto3.client("sts")
        account_id = client.get_caller_identity()["Account"]
        print("Account Id: {}" .format(account_id))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'EndpointConnectionError':
            print("[-] Cant connect to the {} endpoint [-]" .format(region))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
    return account_id

# NOT QUITE WORKING YET
# def get_username(AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY):
#    client = boto3.client("sts", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
#    username = client.get_caller_identity()["Arn"].split(':')[5]
#    print username
#    return username


def check_root_account():
    '''
    use IAM calls to check for root/IAM access
    '''
    client = boto3.client('iam')
    try:
        acct_summary = client.get_account_summary()
        if acct_summary:
            print("Root Key!!! [or IAM access]")
            print("Printing Account Summary")
            pp.pprint(acct_summary['SummaryMap'])

        client_list = client.list_users()
        if client_list:
            print("Printing Users")
            pp.pprint(client_list['Users'])

        print("Checking for console access")
        for user in client_list['Users']:

            try:
                profile = client.get_login_profile(UserName=user['UserName'])
                if profile:
                    print('User {} likely has console access and the password can be reset :-)' .format(user['UserName']))
                    print("Checking for MFA on account")
                    mfa = client.list_mfa_devices(UserName=user['UserName'])
                    print(mfa['MFADevices'])

            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    print("[-]: user '{}' likely doesnt have console access" .format(user['UserName']))
                else:
                    print("Unexpected error: {}" .format(e))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print("{} : Does not have IAM Permissions" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def generic_permission_bruteforcer(service, tests):
    actions = []
    try:
        client = boto3.client(service, region_name=region)
    except Exception as e:
        # print('Failed to connect: "{}"' .format(e.error_message))
        print('Failed to connect: "{}"' .format(e))
        return actions

    actions = generic_method_bruteforcer(service, tests)
    if actions:
        print("\n[+] {} Actions allowed are [+]" .format(service))
        print(actions)
        timenow = datetime.datetime.now()

        db_logger = []
        for action in actions:
            db_logger.append([service, action, AWS_ACCESS_KEY_ID, target, datetime.datetime.now()])
        # print (db_logger)

        # scrapped the json logging idea but keeping it here just in case
        # data = json.dumps({'time' : timenow, 'service' : service, 'actions' : actions, 'target' : 'passed_in_target'})
        # logging.critical(data)

        # logging to db here
        try:
            insert_reconservice_data(db_name, db_logger)
        except sqlite3.OperationalError as e:
            print(e)
            print("You need to set up the database...exiting")
            sys.exit()
        print("\n")
    else:
        print("\n[-] No {} actions allowed [-]" .format(service))
        print("\n")
    return actions


def generic_permission_bruteforcer_region(service, tests, region_passed):
    actions = []
    try:
        client = boto3.client(service, region_name=region)
    except Exception as e:
        # print('Failed to connect: "{}"' .format(e.error_message))
        print('Failed to connect: "{}"' .format(e))
        return actions

    actions = generic_method_bruteforcer_region(service, tests, region_passed)
    if actions:
        print("\n[+] {} Actions allowed are [+]" .format(service))
        print(actions)
        timenow = datetime.datetime.now()

        db_logger = []
        for action in actions:
            db_logger.append([service, action, AWS_ACCESS_KEY_ID, target, datetime.datetime.now()])
        # print (db_logger)

        # scrapped the json logging idea but keeping it here just in case
        # data = json.dumps({'time' : timenow, 'service' : service, 'actions' : actions, 'target' : 'passed_in_target'})
        # logging.critical(data)

        # logging to db here
        try:
            insert_reconservice_data(db_name, db_logger)
        except sqlite3.OperationalError as e:
            print(e)
            print("You need to set up the database...exiting")
            sys.exit()
        print("\n")
    else:
        print("\n[-] No {} actions allowed [-]" .format(service))
        print("\n")
    return actions


def generic_method_bruteforcer(service, tests):
    actions = []
    client = boto3.client(service, region_name=region)
    for api_action, method_name, args, kwargs in tests:
        try:
            method = getattr(client, method_name)
            method(*args, **kwargs)
            # print method --wont return anything on dryrun
        except botocore.exceptions.EndpointConnectionError as e:
            print(e)
            continue
        except KeyboardInterrupt:
            print("CTRL-C received, exiting...")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                print('{} IS allowed' .format(api_action))
                actions.append(api_action)
            elif e.response['Error']['Code'] == 'ClusterNotFoundException':
                print('{} IS allowed but you need to specify a cluster name' .format(api_action))
                actions.append(api_action)
            elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('[-] {} IS allowed - but SubscriptionRequiredException - usually means you have an unconfigured root account [-]' .format(api_action))
                #  If it's not configured, we are not adding it to services
                #  actions.append(api_action)
            elif e.response['Error']['Code'] == 'OptInRequired':
                print('[-] {} IS allowed - but OptInRequired - usually means you have an unconfigured root account [-]' .format(api_action))
                #  If it's not configured, we are not adding it to services
                #  actions.append(api_action)
            else:
                print(e)
                continue
        else:
            print('{} IS allowed' .format(api_action))
            actions.append(api_action)
    return actions


def generic_method_bruteforcer_region(service, tests, region_passed):
    actions = []
    client = boto3.client(service, region_name=region_passed)
    for api_action, method_name, args, kwargs in tests:
        try:
            method = getattr(client, method_name)
            method(*args, **kwargs)
            # print method --wont return anything on dryrun
        except botocore.exceptions.EndpointConnectionError as e:
            print(e)
            continue
        except KeyboardInterrupt:
            print("CTRL-C received, exiting...")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                print('{} IS allowed' .format(api_action))
                actions.append(api_action)
            elif e.response['Error']['Code'] == 'ClusterNotFoundException':
                print('{} IS allowed but you need to specify a cluster name' .format(api_action))
                actions.append(api_action)
            elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('[-] {} IS allowed - but SubscriptionRequiredException - usually means you have an unconfigured root account [-]' .format(api_action))
                actions.append(api_action)
            elif e.response['Error']['Code'] == 'OptInRequired':
                print('[-] {} IS allowed - but OptInRequired - usually means you have an unconfigured root account [-]' .format(api_action))
                actions.append(api_action)
            else:
                print(e)
                continue
        else:
            print('{} IS allowed' .format(api_action))
            actions.append(api_action)
    return actions


def brute_accessanalyzer_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer.html
    '''
    print("### Enumerating AccessAnalyzer Permissions ###")
    tests = [('ListAnalyzers', 'list_analyzers', (), {}, ), ]
    return generic_permission_bruteforcer('accessanalyzer', tests)


def brute_acm_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/acm.html
    '''
    print("### Enumerating ACM Permissions ###")
    tests = [('ListCertificates', 'list_certificates', (), {}, ), ]
    return generic_permission_bruteforcer('acm', tests)


def brute_acm_pca_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/acm-pca.html
    '''
    print("### Enumerating AWS Certificate Manager Private Certificate Authority (ACM-PCA) Permissions ###")
    tests = [('ListCertificateAuthorities', 'list_certificate_authorities', (), {}, ), ]
    return generic_permission_bruteforcer('acm-pca', tests)


def brute_alexaforbusiness_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/alexaforbusiness.html
    '''
    print("### Enumerating Alexa For Business Permissions ###")
    tests = [('CreateAddressBook', 'create_address_book', (), {'Name': 'Test'}, ), ]
    return generic_permission_bruteforcer('alexaforbusiness', tests)

'''
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/amplify.html
'''


def brute_apigateway_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/apigateway.html
    '''
    print("### Enumerating APIGateway Permissions ###")
    tests = [('GetAccount', 'get_account', (), {}, ),
             ('GetApiKeys', 'get_api_keys', (), {}, ),
             ('GetClientCertificates', 'get_client_certificates', (), {}, ),
             ('GetDomainNames', 'get_domain_names', (), {}, ),
             ('GetRestApis', 'get_rest_apis', (), {}, ),
             ('GetSdkTypes', 'get_sdk_types', (), {}, ),
             ('GetUsagePlans', 'get_usage_plans', (), {}, ), ]
    return generic_permission_bruteforcer('apigateway', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigatewaymanagementapi.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigatewayv2.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/appconfig.html

# http://boto3.readthedocs.io/en/latest/reference/services/application-autoscaling.html
# not seeing any functions that dont take args

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/application-insights.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/appmesh.html

def brute_appstream_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/appstream.html
    '''
    print("### Enumerating APPStream Permissions ###")
    tests = [('DescribeFleets', 'describe_fleets', (), {}, ),
             ('DescribeImages', 'describe_images', (), {}, ),
             ('DescribeStacks', 'describe_stacks', (), {}, ), ]
    return generic_permission_bruteforcer('appstream', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/appsync.html
# not seeing any functions that dont take args


def brute_athena_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/athena.html
    '''
    print("### Enumerating Athena Permissions ###")
    tests = [('ListNamedQueries', 'list_named_queries', (), {}, ),
             ('ListQueryExecutions', 'list_query_executions', (), {}, ), ]
    return generic_permission_bruteforcer('athena', tests)


def brute_autoscaling_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/autoscaling.html
    '''
    print("### Enumerating Autoscaling Permissions ###")
    tests = [('DescribeAccountLimits', 'describe_account_limits', (), {}, ),
             ('DescribeAdjustmentTypes', 'describe_adjustment_types', (), {}, ),
             ('DescribeAutoScalingInstances', 'describe_auto_scaling_instances', (), {}, ),
             ('DescribeAutoScalingGroups', 'describe_auto_scaling_groups', (), {}),
             ('DescribeLaunchConfigurations', 'describe_launch_configurations', (), {}),
             ('DescribeScheduledActions', 'describe_scheduled_actions', (), {}),
             ('DescribeTags', 'describe_tags', (), {}, ),
             ('DescribeTerminationPolicyTypes', 'describe_termination_policy_types', (), {}, ),
             ('DescribePolicies', 'describe_policies', (), {}, ), ]
    return generic_permission_bruteforcer('autoscaling', tests)


def brute_autoscaling_plans_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/autoscaling-plans.html
    '''
    print("### Enumerating Autoscaling-Plans Permissions ###")
    tests = [('DescribeScalingPlans', 'describe_scaling_plans', (), {}, ), ]
    return generic_permission_bruteforcer('autoscaling-plans', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html

def brute_batch_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/batch.html
    '''
    print("### Enumerating Batch Permissions ###")
    tests = [('DescribeComputeEnvironments', 'describe_compute_environments', (), {}, ),
             ('DescribeJobDefinitions', 'describe_job_definitions', (), {}, ),
             ('DescribeJobQueues', 'describe_job_queues', (), {}, ), ]
    return generic_permission_bruteforcer('batch', tests)


def brute_budgets_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/budgets.html
    '''
    print("### Enumerating Budgets Permissions ###")
    account_id = get_accountid()
    tests = [('DescribeBudgets', 'describe_budgets', (), {'AccountId': account_id}, ), ]
    return generic_permission_bruteforcer('budgets', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/ce.html
# TODO
# http://boto3.readthedocs.io/en/latest/reference/services/ce.html#CostExplorer.Client.get_cost_and_usage
# shoudl work we just need to generate start and end times each run


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/chime.html

def brute_cloud9_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloud9.html
    '''
    print("### Enumerating Cloud9 Permissions ###")
    tests = [('ListEnvironments', 'list_environments', (), {}, ), ]
    return generic_permission_bruteforcer('cloud9', tests)


def brute_clouddirectory_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/clouddirectory.html
    '''
    print("### Enumerating CloudDirectory Permissions ###")
    tests = [('ListDirectories', 'list_directories', (), {}, ), ]
    return generic_permission_bruteforcer('clouddirectory', tests)


def brute_cloudformation_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudformation.html
    '''
    print("### Enumerating CloudFormation Permissions ###")
    tests = [('ListStacks', 'list_stacks', (), {}),
             ('DescribeStacks', 'describe_stacks', (), {}),
             # ('DescribeStackEvents', 'describe_stack_events', (), {}),
             # ('DescribeStackResources', 'describe_stack_resources', (), {}),
             ('ListExports', 'list_exports', (), {}),
             ('DescribeAccountLimits', 'describe_account_limits', (), {}), ]
    return generic_permission_bruteforcer('cloudformation', tests)


def brute_cloudfront_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudfront.html
    '''
    print("### Enumerating CloudFront Permissions ###")
    tests = [('ListDistributions', 'list_distributions', (), {}),
             ('ListCloudFrontOriginAcessIdentities', 'list_cloud_front_origin_access_identities', (), {}), ]
    return generic_permission_bruteforcer('cloudfront', tests)


def brute_cloudhsm_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudhsm.html
    '''
    print("### Enumerating CloudHSM Permissions ###")
    tests = [('DescribeHsm', 'describe_hsm', (), {}),
             ('ListHsms', 'list_hsms', (), {}),
             ('ListHapgs', 'list_hapgs', (), {}),
             ('DescribeLunaClient', 'describe_luna_client', (), {}),
             ('ListLunaClients', 'list_luna_clients', (), {}), ]
    return generic_permission_bruteforcer('cloudhsm', tests)


def brute_cloudhsmv2_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudhsmv2.html
    '''
    print("### Enumerating CloudHSMv2 Permissions ###")
    tests = [('DescribeBackups', 'describe_backups', (), {}),
             ('DescribeClusters', 'describe_clusters', (), {}), ]
    return generic_permission_bruteforcer('cloudhsmv2', tests)


def brute_cloudsearch_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudsearch.html
    '''
    print("### Enumerating CloudSearch Permissions ###")
    tests = [('DescribeDomains', 'describe_domains', (), {}, ),
             ('ListDomainNames', 'list_domain_names', (), {}, ), ]
    return generic_permission_bruteforcer('cloudsearch', tests)


def brute_cloudsearchdomain_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudsearchdomain.html
    Disabled---requires a custom search domain from cloudsearch describe_domains results
    '''
    print("### Enumerating Amazon CloudSearch Domain Permissions ###")
    tests = [('Search', 'search', (), {'query': '*'}, ), ]
    return generic_permission_bruteforcer('cloudsearchdomain', tests)


def brute_cloudtrail_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudtrail.html
    '''
    print("### Enumerating CloudTrail Permissions ###")
    tests = [('DescribeTrails', 'describe_trails', (), {}, ),
             ('ListPublicKeys', 'list_public_keys', (), {}, ), ]
    return generic_permission_bruteforcer('cloudtrail', tests)


def brute_cloudwatch_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cloudwatch.html
    '''
    print("### Enumerating CloudWatch Permissions ###")
    tests = [('ListMetrics', 'list_metrics', (), {}, ),
             ('DescribeAlarmHistory', 'describe_alarm_history', (), {}, ),
             ('DescribeAlarms', 'describe_alarms', (), {}, ), ]
    return generic_permission_bruteforcer('cloudwatch', tests)


def brute_codebuild_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/codebuild.html
    '''
    print("### Enumerating CodeBuild Permissions ###")
    tests = [('ListBuilds', 'list_builds', (), {}, ),
             ('ListCuratedEnvironmentImages', 'list_curated_environment_images', (), {}, ),
             ('ListProjects', 'list_projects', (), {}, ), ]
    return generic_permission_bruteforcer('codebuild', tests)


def brute_codecommit_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/codecommit.html
    '''
    print("### Enumerating CodeCommit Permissions ###")
    tests = [('ListRepositories', 'list_repositories', (), {}, ), ]
    return generic_permission_bruteforcer('codecommit', tests)


def brute_codedeploy_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/codedeploy.html
    '''
    print("### Enumerating CodeDeploy Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}, ),
             ('ListDeployments', 'list_deployments', (), {}, ),
             ('ListDeploymentsConfigs', 'list_deployment_configs', (), {}, ),
             ('ListGitHubAccountTokenNames', 'list_git_hub_account_token_names', (), {}, ),
             ('ListOnPremisesInstances', 'list_on_premises_instances', (), {}, ), ]
    return generic_permission_bruteforcer('codedeploy', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codeguru-reviewer.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codeguruprofiler.html


def brute_codepipeline_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/codepipeline.html
    '''
    print("### Enumerating CodePipeline Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}, ), ]
    return generic_permission_bruteforcer('codepipeline', tests)


def brute_codestar_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/codestar.html
    '''
    print("### Enumerating CodeStar Permissions ###")
    tests = [('ListProjects', 'list_projects', (), {}, ),
             ('ListUerProfiles', 'list_user_profiles', (), {}, ), ]
    return generic_permission_bruteforcer('codestar', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codestar-connections.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codestar-notifications.html

def brute_cognitoidentity_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cognito-identity.html
    '''
    print("### Enumerating Cognito-Identity Permissions ###")
    tests = [('ListIdentityPools', 'list_identity_pools', (), {'MaxResults': 1}, ), ]
    return generic_permission_bruteforcer('cognito-identity', tests)


def brute_cognitoidp_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cognito-idp.html
    '''
    print("### Enumerating CognitoIdentityProvider Permissions ###")
    tests = [('ListUserPools', 'list_user_pools', (), {'MaxResults': 1}, ), ]
    return generic_permission_bruteforcer('cognito-idp', tests)


def brute_cognitosync_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cognito-sync.html
    '''
    print("### Enumerating CognitoSync Permissions ###")
    tests = [('ListIdentityPoolUsage', 'list_identity_pool_usage', (), {}, ), ]
    return generic_permission_bruteforcer('cognito-sync', tests)


def brute_comprehend_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/comprehend.html
    '''
    print("### Enumerating Comprehend Permissions ###")
    tests = [('ListTopicsDetectionJobs', 'list_topics_detection_jobs', (), {}, ), ]
    return generic_permission_bruteforcer('comprehend', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehendmedical.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/compute-optimizer.html


def brute_configservice_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/config.html
    '''
    print("### Enumerating ConfigService Permissions ###")
    tests = [('DescribeComplianceByConfigRule', 'describe_compliance_by_config_rule', (), {}, ),
             ('DescribeComplianceByResource', 'describe_compliance_by_resource', (), {}, ),
             ('DescribeConfigRuleEvaluationStatus', 'describe_config_rule_evaluation_status', (), {}, ),
             ('DescribeConfigurationRecorders', 'describe_configuration_recorders', (), {}, ),
             ('DescribeConfigRules', 'describe_config_rules', (), {}, ),
             ('DescribeConfigurationRecorderStatus', 'describe_configuration_recorder_status', (), {}, ),
             ('DescribeDeliveryChannelStatus', 'describe_delivery_channel_status', (), {}, ),
             ('DescribeDeliveryChannels', 'describe_delivery_channels', (), {}, ), ]
    return generic_permission_bruteforcer('config', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/connect.html
# no functions

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/connectparticipant.html


def brute_costandusagereportservice_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cur.html
    '''
    print("### Enumerating CostandUsageReportService Permissions ###")
    tests = [('DescribeReportDefinitions', 'describe_report_definitions', (), {}, ), ]
    return generic_permission_bruteforcer('cur', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dataexchange.html

def brute_datapipeline_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/datapipeline.html
    '''
    print("### Enumerating DataPipeline Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}, ), ]
    return generic_permission_bruteforcer('datapipeline', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/datasync.html


def brute_dax_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/dax.html
    '''
    print("### Enumerating DynamoDB Accelerator (DAX) Permissions ###")
    tests = [('DescribeClusters', 'describe_clusters', (), {}, ),
             ('DescribeDefaultParameters', 'describe_default_parameters', (), {}, ),
             ('DescribeEvents', 'describe_events', (), {}, ),
             ('DescribeParameterGroups', 'describe_parameter_groups', (), {}, ),
             ('DescribeSubnetGroups', 'describe_subnet_groups', (), {}, ), ]
    return generic_permission_bruteforcer('dax', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/detective.html

def brute_devicefarm_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/devicefarm.html
    http://docs.aws.amazon.com/general/latest/gr/rande.html#devicefarm_region
    '''
    print("### Enumerating DeviceFarm Permissions ###")
    tests = [('ListProjects', 'list_projects', (), {}, ),
             ('ListDevices', 'list_devices', (), {}, ), ]
    return generic_permission_bruteforcer_region('devicefarm', tests, 'us-west-2')


def brute_directconnect_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/directconnect.html
    '''
    print("### Enumerating DirectConnect Permissions ###")
    tests = [('DescribeConnections', 'describe_connections', (), {}, ),
             ('DescribeLags', 'describe_lags', (), {}, ), ]
    return generic_permission_bruteforcer('directconnect', tests)


def brute_applicationdiscoveryservice_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/discovery.html
    '''
    print("### Enumerating ApplicationDiscoveryService Permissions ###")
    tests = [('DescribeAgents', 'describe_agents', (), {}, ), ]
    return generic_permission_bruteforcer_region('discovery', tests, 'us-west-2')


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dlm.html


def brute_dms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/dms.html
    '''
    print("### Enumerating DatabaseMigrationService Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}, ),
             ('DescribeEvents', 'describe_events', (), {}, ),
             ('DescribeConnections', 'describe_connections', (), {}, ), ]
    return generic_permission_bruteforcer('dms', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/docdb.html


def brute_directoryservice_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ds.html
    '''
    print("### Enumerating DirectoryService Permissions ###")
    tests = [('DescribeDirectories', 'describe_directories', (), {}, ),
             ('DescribeSnapshots', 'describe_snapshots', (), {}, ),
             ('DescribeTrusts', 'describe_trusts', (), {}, ), ]
    return generic_permission_bruteforcer('ds', tests)


def brute_dynamodb_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html
    '''
    print("### Enumerating DynamoDB Permissions ###")
    tests = [('ListTables', 'list_tables', (), {}, ),
             ('DescribeLimits', 'describe_limits', (), {}, ),
             ('ListBackups', 'list_backups', (), {}, ),
             ('ListGlobalTables', 'list_global_tables', (), {}, ), ]
    return generic_permission_bruteforcer('dynamodb', tests)


def brute_dynamodbstreams_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/dynamodbstreams.html
    '''
    print("### Enumerating DynamoDBStreamsPermissions ###")
    tests = [('ListStreams', 'list_streams', (), {}, ), ]
    return generic_permission_bruteforcer('dynamodbstreams', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs.html


def brute_ec2_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#client
    '''
    print("### Enumerating EC2 Permissions ###")
    tests = [('DescribeInstances', 'describe_instances', (), {'DryRun': True}, ),
             ('DescribeInstanceStatus', 'describe_instance_status', (), {'DryRun': True}, ),
             ('DescribeImages', 'describe_images', (), {'DryRun': True, 'Owners': ['self', ]}, ),
             ('CreateImage', 'create_image', (), {'InstanceId': 'i-0ffffeeeeaa11e111', 'Name': 'testimage', 'DryRun': True}, ),
             ('DescribeVolumes', 'describe_volumes', (), {'DryRun': True}, ),
             ('CreateVolume', 'create_volume', (), {'AvailabilityZone': 'us-east-1a', 'Size': 8, 'DryRun': True}, ),
             ('DescribeSnapshots', 'describe_snapshots', (), {'DryRun': True, 'OwnerIds': ['self', ]}, ),
             # ('CreateSnapshot', 'create_snapshot', (), {'VolumeId': 'vol-05777eab71bc97dcb', 'DryRun': True}, ),
             ('DescribeAccountAttributes', 'describe_account_attributes', (), {'DryRun': True}, ),
             ('DescribeAddresses', 'describe_addresses', (), {'DryRun': True}, ),
             ('DescribeAvailabilityZones', 'describe_availability_zones', (), {'DryRun': True}, ),
             ('DescribeBundleTasks', 'describe_bundle_tasks', (), {'DryRun': True}, ),
             ('DescribeClassicLinkInstances', 'describe_classic_link_instances', (), {'DryRun': True}, ),
             ('DescribeConversionTasks', 'describe_conversion_tasks', (), {'DryRun': True}, ),
             ('DescribeCustomerGateways', 'describe_customer_gateways', (), {'DryRun': True}, ),
             ('DescribeDhcpOptions', 'describe_dhcp_options', (), {'DryRun': True}, ),
             ('DescribeEgressOnlyInternetGateways', 'describe_egress_only_internet_gateways', (), {'DryRun': True}, ),

             # The above is more than enough to decide that all/almost all EC2 permissions are there but
             # I'm putting all of them so they can be used for information gathering later and i can keep the
             # ec2 tests blocks consistent across modules

             ('DescribeExportTasks', 'describe_export_tasks', (), {}, ),
             ('DescribeFlowLogs', 'describe_flow_logs', (), {}, ),
             ('DescribeHostReservations', 'describe_host_reservations', (), {}, ),
             ('DescribeHosts', 'describe_hosts', (), {}, ),
             ('DescribeIamInstanceProfileAssociations', 'describe_iam_instance_profile_associations', (), {}, ),
             ('DescribeImportImageTasks', 'describe_import_image_tasks', (), {'DryRun': True}, ),
             ('DescribeImportSnapshotTasks', 'describe_import_snapshot_tasks', (), {'DryRun': True}, ),
             ('DescribeInternetGateways', 'describe_internet_gateways', (), {'DryRun': True}, ),
             ('DescribeKeyPairs', 'describe_key_pairs', (), {'DryRun': True}, ),
             ('CreateKeyPair', 'create_key_pair', (), {'KeyName': 'asdfg12345', 'DryRun': True}, ),
             ('DescribeLaunchTemplates', 'describe_launch_templates', (), {'DryRun': True}, ),
             ('DescribeMovingAddresses', 'describe_moving_addresses', (), {'DryRun': True}, ),
             ('DescribeNatGateways', 'describe_nat_gateways', (), {}, ),
             ('DescribeNetworkAcls', 'describe_network_acls', (), {'DryRun': True}, ),
             ('DescribeNetworkInterfaces', 'describe_network_interfaces', (), {'DryRun': True}, ),
             ('DescribePlacementGroups', 'describe_placement_groups', (), {'DryRun': True}, ),
             ('DescribePrefixLists', 'describe_prefix_lists', (), {'DryRun': True}, ),
             ('DescribeReservedInstances', 'describe_reserved_instances', (), {'DryRun': True}, ),
             ('DescribeReservedInstancesListings', 'describe_reserved_instances_listings', (), {}, ),
             ('DescribeReservedInstancesModifications', 'describe_reserved_instances_modifications', (), {}, ),
             ('DescribeRouteTables', 'describe_route_tables', (), {'DryRun': True}, ),
             ('DescribeScheduledInstances', 'describe_scheduled_instances', (), {'DryRun': True}, ),
             ('DescribeSecurityGroups', 'describe_security_groups', (), {'DryRun': True}, ),
             ('DescribeSpotDatafeedSubscription', 'describe_spot_datafeed_subscription', (), {'DryRun': True}, ),
             ('DescribeSubnets', 'describe_subnets', (), {'DryRun': True}, ),
             ('DescribeTags', 'describe_tags', (), {'DryRun': True}, ),
             ('DescribeVolumeStatus', 'describe_volume_status', (), {'DryRun': True}, ),
             ('DescribeVpcClassicLink', 'describe_vpc_classic_link', (), {'DryRun': True}, ),
             ('DescribeVpcClassicLinkDnsSupport', 'describe_vpc_classic_link_dns_support', (), {}, ),
             ('DescribeVpcEndpointServices', 'describe_vpc_endpoint_services', (), {'DryRun': True}, ),
             ('DescribeVpcEndpoints', 'describe_vpc_endpoints', (), {'DryRun': True}, ),
             ('DescribeVpcPeeringConnections', 'describe_vpc_peering_connections', (), {'DryRun': True}, ),
             ('DescribeVpcs', 'describe_vpcs', (), {'DryRun': True}, ),
             ('CreateVpc', 'create_vpc', (), {'CidrBlock': '10.0.0.0/16', 'DryRun': True}, ),
             ('DescribeVpnConnections', 'describe_vpn_connections', (), {'DryRun': True}, ),
             ('DescribeVpnGateways', 'describe_vpn_gateways', (), {'DryRun': True}, ), ]
    return generic_permission_bruteforcer('ec2', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2-instance-connect.html


def brute_ecr_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ecr.html
    '''
    print("### Enumerating EC2 Container Registry (ECR) Permissions ###")
    tests = [('DescribeRepositories', 'describe_repositories', (), {}), ]
    return generic_permission_bruteforcer('ecr', tests)


def brute_ecs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ecs.html
    '''
    print("### Enumerating EC2 Container Service (ECS) Permissions ###")
    tests = [('ListClusters', 'list_clusters', (), {}),
             ('DescribeClusters', 'describe_clusters', (), {}),
             ('ListContainerInstances', 'list_container_instances', (), {}),
             ('ListTaskDefinitions', 'list_task_definitions', (), {}),
             # ('ListTasks', 'list_tasks', (), {}), #needs a cluster name
             ]
    return generic_permission_bruteforcer('ecs', tests)


def brute_efs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/efs.html
    '''
    print("### Enumerating Elastic File System (EFS) Permissions ###")
    tests = [('DescribeFileSystems', 'describe_file_systems', (), {}),
             ('DescribeMountTargets', 'describe_mount_targets', (), {}), ]
    return generic_permission_bruteforcer('efs', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elastic-inference.html


def brute_elasticache_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/elasticache.html
    '''
    print("### Enumerating ElastiCache Permissions ###")
    tests = [('DescribeCacheClusters', 'describe_cache_clusters', (), {}),
             ('DescribeCacheEngineVersions', 'describe_cache_engine_versions', (), {}),
             ('DescribeCacheSecurityGroups', 'describe_cache_security_groups', (), {}),
             ('DescribeCacheSubnetGroups', 'describe_cache_subnet_groups', (), {}),
             ('DescribeEvents', 'describe_events', (), {}),
             ('DescribeReplicationGroups', 'describe_replication_groups', (), {}),
             ('DescribeReservedCacheNodes', 'describe_reserved_cache_nodes', (), {}),
             ('DescribeReservedCacheNodesOfferings', 'describe_reserved_cache_nodes_offerings', (), {}),
             ('DescribeSnapshots', 'describe_snapshots', (), {}), ]
    return generic_permission_bruteforcer('elasticache', tests)


def brute_elasticbeanstalk_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/elasticbeanstalk.html
    '''
    print("### Enumerating ElasticBeanstalk Permissions ###")
    tests = [('DescribeApplications', 'describe_applications', (), {}),
             ('DescribeApplicationVersions', 'describe_application_versions', (), {}),
             ('DescribeConfigurationOptions', 'describe_configuration_options', (), {}),
             ('DescribeEnvironments', 'describe_environments', (), {}),
             ('DescribeEnvironmentHealth', 'describe_environment_health', (), {}),
             ('DescribeEnvironmentManagedActionHistory', 'describe_environment_managed_action_history', (), {}),
             ('DescribeEnvironmentManagedActions', 'describe_environment_managed_actions', (), {}),
             ('DescribeEvents', 'describe_events', (), {}),
             ('DescribeInstancesHealth', 'describe_instances_health', (), {}), ]
    return generic_permission_bruteforcer('elasticbeanstalk', tests)


def brute_elastictranscoder_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/elastictranscoder.html
    '''
    print("### Enumerating ElasticTranscoder Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}),
             ('ListPresets', 'list_presets', (), {}), ]
    return generic_permission_bruteforcer('elastictranscoder', tests)


def brute_elasticloadbalancing_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/elb.html
    '''
    print("### Enumerating ElasticLoadBalancing Permissions ###")
    tests = [('DescribeLoadBalancers', 'describe_load_balancers', (), {}),
             ('DescribeAccountLimits', 'describe_account_limits', (), {}), ]
    return generic_permission_bruteforcer('elb', tests)


def brute_elasticloadbalancingv2_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/elbv2.html
    '''
    print("### Enumerating ElasticLoadBalancing Permissions ###")
    tests = [('DescribeLoadBalancers', 'describe_load_balancers', (), {}),
             ('DescribeAccountLimits', 'describe_account_limits', (), {}),
             ('DescribeListeners', 'describe_listeners', (), {}),
             ('DescribeTargetGroups', 'describe_target_groups', (), {}), ]
    return generic_permission_bruteforcer('elbv2', tests)


def brute_emr_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/emr.html
    '''
    print("### Enumerating Elastic MapReduce (EMR) Permissions ###")
    tests = [('ListClusters', 'list_clusters', (), {}),
             ('ListSecurityConfigurations', 'list_security_configurations', (), {}), ]
    return generic_permission_bruteforcer('emr', tests)


def brute_es_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/es.html
    '''
    print("### Enumerating Elasticsearch Service Permissions ###")
    tests = [('ListDomainNames', 'list_domain_names', (), {}),
             ('ListElasticsearchVersions', 'list_elasticsearch_versions', (), {}), ]
    return generic_permission_bruteforcer('es', tests)


def brute_cloudwatchevents_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/events.html
    '''
    print("### Enumerating CloudWatch Events Permissions ###")
    tests = [('ListRules', 'list_rules', (), {}), ]
    return generic_permission_bruteforcer('events', tests)


def brute_firehose_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/firehose.html
    '''
    print("### Enumerating Kinesis Firehose Permissions ###")
    tests = [('ListDeliveryStreams', 'list_delivery_streams', (), {}), ]
    return generic_permission_bruteforcer('firehose', tests)


def brute_fms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/fms.html
    '''
    print("### Enumerating Firewall Management Service (FMS) Permissions ###")
    tests = [('ListPolicies', 'list_policies', (), {}), ]
    return generic_permission_bruteforcer('fms', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/forecast.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/forecastquery.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/frauddetector.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/fsx.html


def brute_gamelift_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/gamelift.html
    '''
    print("### Enumerating GameLift Permissions ###")
    tests = [('ListAliases', 'list_aliases', (), {}),
             ('ListBuilds', 'list_builds', (), {}),
             ('ListFleets', 'list_fleets', (), {}),
             ('DescribeEC2InstanceLimits', 'describe_ec2_instance_limits', (), {}),
             ('DescribeFleetAttributes', 'describe_fleet_attributes', (), {}),
             ('DescribeFleetCapacity', 'describe_fleet_capacity', (), {}),
             ('DescribeGameSessionQueues', 'describe_game_session_queues', (), {}), ]
    return generic_permission_bruteforcer('gamelift', tests)


def brute_glacier_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/glacier.html
    '''
    print("### Enumerating Glacier Permissions ###")
    tests = [('ListVaults', 'list_vaults', (), {}), ]
    return generic_permission_bruteforcer('glacier', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/globalaccelerator.html


def brute_glue_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/glue.html
    '''
    print("### Enumerating Glue Permissions ###")
    tests = [('GetDatabases', 'get_databases', (), {}),
             ('GetClassifiers', 'get_classifiers', (), {}),
             ('GetConnections', 'get_connections', (), {}),
             ('GetCrawlerMetrics', 'get_crawler_metrics', (), {}),
             ('GetCrawlers', 'get_crawlers', (), {}),
             ('GetDevEndpoints', 'get_dev_endpoints', (), {}),
             ('GetJobs', 'get_jobs', (), {}),
             ('GetTriggers', 'get_triggers', (), {}), ]
    return generic_permission_bruteforcer('glue', tests)


def brute_greengrass_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/greengrass.html
    If this one doesnt work make sure boto3 is up to date
    '''
    print("### Enumerating Greegrass Permissions ###")
    tests = [('ListGroups', 'list_groups', (), {}),
             ('ListLoggerDefinitions', 'list_logger_definitions', (), {}),
             ('ListSubscriptionDefinitions', 'list_subscription_definitions', (), {}), ]
    return generic_permission_bruteforcer('greengrass', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/groundstation.html

def brute_guardduty_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/guardduty.html
    '''
    print("### Enumerating Guard Duty Permissions ###")
    tests = [('ListDetectors', 'list_detectors', (), {}),
             ('ListInvitations', 'list_invitations', (), {}), ]
    return generic_permission_bruteforcer('guardduty', tests)


def brute_health_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/health.html
    '''
    print("### Enumerating Health Permissions ###")
    tests = [('DescribeEvents', 'describe_events', (), {}),
             ('DescribeEntityAggregates', 'describe_entity_aggregates', (), {}),
             ('DescribeEventTypes', 'describe_event_types', (), {}), ]
    return generic_permission_bruteforcer('health', tests)


def brute_iam_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/iam.html
    TODO chop out the ARN/username and make some more fun function calls must chop up ARN to get username
    '''
    print("### Enumerating IAM Permissions ###")
    # account_username = get_username()
    tests = [('GetUser', 'get_user', (), {}),
             # ('ListUserPolicies', 'list_user_policies', (), {'UserName':'root'} ),
             ('ListGroups', 'list_groups', (), {}),
             ('ListUsers', 'list_users', (), {}),
             ('ListRoles', 'list_roles', (), {}),
             ('ListPolicies', 'list_policies', (), {}),
             # ('ListGroupsForUser', 'list_groups_for_user', (), {'UserName':account_username} ),
             ('GetCredentialReport', 'get_credential_report', (), {}),
             ('GetAccountSummary', 'get_account_summary', (), {}),
             ('GetAccountAuthorizationDetails', 'get_account_authorization_details', (), {}), ]
    return generic_permission_bruteforcer('iam', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/imagebuilder.html


def brute_importexport_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/importexport.html
    '''
    print("### Enumerating Import/Export Permissions ###")
    tests = [('ListJobs', 'list_jobs', (), {}), ]
    return generic_permission_bruteforcer('importexport', tests)


def brute_inspector_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/inspector.html
    '''
    print("### Enumerating Inspector Permissions ###")
    tests = [('ListFindings', 'list_findings', (), {}),
             ('ListEventSubscriptions', 'list_event_subscriptions', (), {}),
             ('ListAssessmentRuns', 'list_assessment_runs', (), {}),
             ('ListAssessmentTargets', 'list_assessment_targets', (), {}), ]
    return generic_permission_bruteforcer('inspector', tests)


def brute_iot_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/iot.html
    '''
    print("### Enumerating IoT Permissions ###")
    tests = [('ListThings', 'list_things', (), {}),
             ('ListPolicies', 'list_policies', (), {}),
             ('ListCertificates', 'list_certificates', (), {}), ]
    return generic_permission_bruteforcer('iot', tests)


def brute_iotdata_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/iot-data.html
    NO functions to call without data
    '''
    print("### Enumerating IoT Data Plane Permissions ###")
    tests = [('', '', (), {}), ]
    return generic_permission_bruteforcer('iot-data', tests)


# http://boto3.readthedocs.io/en/latest/reference/services/iot-jobs-data.html
# NO functions to call without data

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iot1click-devices.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iot1click-projects.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotanalytics.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotevents.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotevents-data.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotsecuretunneling.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotsitewise.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotthingsgraph.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kendra.html


def brute_kinesis_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kinesis.html
    '''
    print("### Enumerating Kinesis Permissions ###")
    tests = [('ListStreams', 'list_streams', (), {}), ]
    return generic_permission_bruteforcer('kinesis', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/kinesis-video-archived-media.html
# NO functions to call without data

# http://boto3.readthedocs.io/en/latest/reference/services/kinesis-video-media.html
# NO functions to call without data

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesis-video-signaling.html


def brute_kinesisanalytics_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kinesisanalytics.html
    '''
    print("### Enumerating Kinesis Analytics Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}), ]
    return generic_permission_bruteforcer('kinesisanalytics', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesisanalyticsv2.html


def brute_kinesisvideo_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kinesisvideo.html
    '''
    print("### Enumerating Kinesis Video Permissions ###")
    tests = [('ListStreams', 'list_streams', (), {}), ]
    return generic_permission_bruteforcer('kinesisvideo', tests)


def brute_kms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kms.html
    '''
    print("### Enumerating Key Management Service (KMS) Permissions ###")
    tests = [('ListKeys', 'list_keys', (), {}),
             ('ListAliases', 'list_aliases', (), {}), ]
    return generic_permission_bruteforcer('kms', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lakeformation.html


def brute_lambda_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/lambda.html
    '''
    print("### Enumerating Lambda Permissions ###")
    tests = [('ListFunctions', 'list_functions', (), {}, ),
             ('GetAccountSettings', 'get_account_settings', (), {}),
             ('ListEventSourceMappings', 'list_event_source_mappings', (), {}), ]
    return generic_permission_bruteforcer('lambda', tests)


def brute_lexmodels_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/lex-models.html
    '''
    print("### Enumerating Lex Model Building Service Permissions ###")
    tests = [('GetBots', 'get_bots', (), {}),
             ('GetIntents', 'get_intents', (), {}), ]
    return generic_permission_bruteforcer('lex-models', tests)


def brute_lexruntime_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/lex-runtime.html
    NO functions to call without data
    '''
    print("### Enumerating Lex Runtime Permissions ###")
    tests = [('', '', (), {}), ]
    return generic_permission_bruteforcer('lex-runtime', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/license-manager.html


def brute_lightsail_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/lightsail.html
    '''
    print("### Enumerating Lightsail Permissions ###")
    tests = [('GetDomains', 'get_domains', (), {}),
             ('GetBundles', 'get_bundles', (), {}),
             ('GetInstances', 'get_instances', (), {}),
             ('GetKeyPairs', 'get_key_pairs', (), {}),
             ('GetOperations', 'get_operations', (), {}),
             ('GetRegions', 'get_regions', (), {}), ]
    return generic_permission_bruteforcer('lightsail', tests)


def brute_cloudwatchlogs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/logs.html
    '''
    print("### Enumerating CloudWatch Logs Permissions ###")
    tests = [('DescribeDestinations', 'describe_destinations', (), {}),
             ('DescribeExportTasks', 'describe_export_tasks', (), {}),
             ('DescribeLogGroups', 'describe_log_groups', (), {}), ]
    return generic_permission_bruteforcer('logs', tests)


def brute_machinelearning_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/machinelearning.html
    http://docs.aws.amazon.com/general/latest/gr/rande.html#machinelearning_region <--allowed regions for ML
    '''
    print("### Enumerating Machine Learning Permissions ###")
    tests = [('DescribeDataSources', 'describe_data_sources', (), {}),
             ('DescribeEvaluations', 'describe_evaluations', (), {}), ]
    return generic_permission_bruteforcer('machinelearning', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/macie.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/macie2.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/managedblockchain.html

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/marketplace-catalog.html


# http://boto3.readthedocs.io/en/latest/reference/services/marketplace-entitlement.html
# NO functions to call without arguements

# http://boto3.readthedocs.io/en/latest/reference/services/marketplacecommerceanalytics.html
# NO functions to call without arguements

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediaconnect.html


def brute_mediaconvert_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediaconvert.html
    '''
    print("### Enumerating AWS Elemental MediaConvert Permissions ###")
    tests = [('ListJobs', 'list_jobs', (), {}),
             ('ListJobTemplates', 'list_job_templates', (), {}),
             ('ListPresets', 'list_presets', (), {}),
             ('ListQueues', 'list_queues', (), {}), ]
    return generic_permission_bruteforcer('mediaconvert', tests)


def brute_medialive_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/medialive.html
    '''
    print("### Enumerating AWS Elemental MediaLive Permissions ###")
    tests = [('ListChannels', 'list_channels', (), {}),
             ('ListInputSecurityGroups', 'list_input_security_groups', (), {}),
             ('ListInputs', 'list_inputs', (), {}), ]
    return generic_permission_bruteforcer('medialive', tests)


def brute_mediapackage_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediapackage.html
    '''
    print("### Enumerating AWS Elemental MediaPackage Permissions ###")
    tests = [('ListChannels', 'list_channels', (), {}),
             ('ListOriginEndpoints', 'list_origin_endpoints', (), {}), ]
    return generic_permission_bruteforcer('mediapackage', tests)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediapackage-vod.html


def brute_mediastore_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediastore.html
    '''
    print("### Enumerating AWS Elemental MediaStore Permissions ###")
    tests = [('ListContainers', 'list_containers', (), {}), ]
    return generic_permission_bruteforcer('mediastore', tests)


def brute_mediastore_data_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediastore-data.html
    Could not connect to the endpoint URL: "https://data.mediastore.us-east-1.amazonaws.com/"
    boto3 (1.7.4) bug
    '''
    print("### Enumerating AWS Elemental MediaStore Permissions ###")
    tests = [('ListItems', 'list_items', (), {}), ]
    return generic_permission_bruteforcer('mediastore-data', tests)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediatailor.html


# http://boto3.readthedocs.io/en/latest/reference/services/meteringmarketplace.html
# NO functions to call without arguements


def brute_mgh_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mgh.html
    '''
    print("### Enumerating AWS Migration Hub Permissions ###")
    tests = [('ListMigrationTasks', 'list_migration_tasks', (), {}),
             ('ListProgressUpdateStreams', 'list_progress_update_streams', (), {}), ]
    return generic_permission_bruteforcer_region('mgh', tests, 'us-west-2')


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/migrationhub-config.html


def brute_mobile_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mobile.html
    '''
    print("### Enumerating AWS Mobile Permissions ###")
    tests = [('ListBundles', 'list_bundles', (), {}),
             ('ListProjects', 'list_projects', (), {}), ]
    return generic_permission_bruteforcer('mobile', tests)


def brute_mq_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mq.html
    '''
    print("### Enumerating AmazonMQ Permissions ###")
    tests = [('ListBrokers', 'list_brokers', (), {}),
             ('ListConfigurations', 'list_configurations', (), {}), ]
    return generic_permission_bruteforcer('mq', tests)


def brute_mturk_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mturk.html
    '''
    print("### Enumerating Mechanical Turk (MTurk) Permissions ###")
    tests = [('GetAccountBalance', 'get_account_balance', (), {}),
             ('ListHits', 'list_hits', (), {}),
             ('ListWorkerBlocks', 'list_worker_blocks', (), {}), ]
    return generic_permission_bruteforcer('mturk', tests)


def brute_opsworks_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/opsworks.html
    Everything else requires a stackID to get the instance/app/volume info per stack
    '''
    print("### Enumerating OpsWorks Permissions ###")
    tests = [('DescribeUserProfiles', 'describe_user_profiles', (), {}),
             ('DescribeStacks', 'describe_stacks', (), {}), ]
    return generic_permission_bruteforcer('opsworks', tests)


def brute_opsworkscm_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/opsworkscm.html
    '''
    print("### Enumerating OpsWorks for Chef Automate Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}),
             ('DescribeBackups', 'describe_backups', (), {}),
             ('DescribeServers', 'describe_servers', (), {}), ]
    return generic_permission_bruteforcer('opsworkscm', tests)


def brute_organizations_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/organizations.html
    '''
    print("### Enumerating Organizations Permissions ###")
    tests = [('DescribeOrganization', 'describe_organization', (), {}),
             ('ListAccounts', 'list_accounts', (), {}),
             ('ListCreateAccountStatus', 'list_create_account_status', (), {}),
             ('ListHandshakesForAccount', 'list_handshakes_for_account', (), {}),
             ('ListHandshakesForOrganization', 'list_handshakes_for_organization', (), {}),
             ('ListPolicies', 'list_policies', (), {'Filter': 'SERVICE_CONTROL_POLICY'}),
             ('ListRoots', 'list_roots', (), {}), ]
    return generic_permission_bruteforcer('organizations', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/pinpoint.html
# NO functions to call without arguements


def brute_polly_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/polly.html
    '''
    print("### Enumerating Polly Permissions ###")
    tests = [('DescribeVoices', 'describe_voices', (), {}),
             ('ListLexicons', 'list_lexicons', (), {}), ]
    return generic_permission_bruteforcer('polly', tests)


def brute_pricing_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/pricing.html
    '''
    print("### Enumerating AWS Price List Service (Pricing) Permissions ###")
    tests = [('DescribeServices', 'describe_services', (), {}), ]
    return generic_permission_bruteforcer('pricing', tests)


def brute_rds_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/rds.html
    '''
    print("### Enumerating RDS Permissions ###")
    tests = [('DescribeDBInstances', 'describe_db_instances', (), {}),
             ('DescribeDBSecurityGroups', 'describe_db_security_groups', (), {}),
             ('DescribeDBSnapshots', 'describe_db_snapshots', (), {}),
             ('DescribeDBClusters', 'describe_db_clusters', (), {}),
             ('DescribeDBClusterSnapshots', 'describe_db_cluster_snapshots', (), {}),
             ('DescribeAccountAttributes', 'describe_account_attributes', (), {}),
             ('DescribeEvents', 'describe_events', (), {}),
             ('DescribeReservedDBInstances', 'describe_reserved_db_instances', (), {}), ]
    return generic_permission_bruteforcer('rds', tests)


def brute_redshift_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/redshift.html
    '''
    print("### Enumerating Redshift Permissions ###")
    tests = [('DescribeClusters', 'describe_clusters', (), {}),
             ('DescribeClusterSecurityGroups', 'describe_cluster_security_groups', (), {}),
             ('DescribeClusterSnapshots', 'describe_cluster_snapshots', (), {}),
             ('DescribeClusterParameterGroup', 'describe_cluster_parameter_groups', (), {}),
             ('DescribeEvents', 'describe_events', (), {}),
             ('DescribeHSMConfigurations', 'describe_hsm_configurations', (), {}), ]
    return generic_permission_bruteforcer('redshift', tests)


def brute_rekognition_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/rekognition.html
    '''
    print("### Enumerating Rekognition Permissions ###")
    tests = [('ListCollections', 'list_collections', (), {}), ]
    return generic_permission_bruteforcer('rekognition', tests)


def brute_resource_groups_permissions():
    '''
    # http://boto3.readthedocs.io/en/latest/reference/services/resource-groups.html
    '''
    print("### Enumerating AWS Resource Groups Permissions ###")
    tests = [('ListGroups', 'list_groups', (), {}), ]
    return generic_permission_bruteforcer('resource-groups', tests)


def brute_resourcegroupstaggingapi_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/resourcegroupstaggingapi.html
    '''
    print("### Enumerating AWS Resource Groups Tagging API Permissions ###")
    tests = [('GetResources', 'get_resources', (), {}), ]
    return generic_permission_bruteforcer('resourcegroupstaggingapi', tests)


def brute_route53_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/route53.html
    '''
    print("### Enumerating Route53 Permissions ###")
    tests = [('ListHostedZones', 'list_hosted_zones', (), {}),
             ('ListHostedZonesByName', 'list_hosted_zones_by_name', (), {}),
             ('ListGeoLocations', 'list_geo_locations', (), {}),
             ('ListHealthChecks', 'list_health_checks', (), {}),
             ('ListTrafficPolicies', 'list_traffic_policies', (), {}), ]
    return generic_permission_bruteforcer('route53', tests)


def brute_route53domains_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/route53domains.html
    '''
    print("### Enumerating Route53 Domains Permissions ###")
    tests = [('ListDomains', 'list_domains', (), {}),
             ('ListOperations', 'list_operations', (), {}), ]
    return generic_permission_bruteforcer('route53domains', tests)


def brute_s3_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/s3.html
    '''
    print("### Enumerating S3 Permissions ###")
    tests = [('ListBuckets', 'list_buckets', (), {}), ]
    return generic_permission_bruteforcer('s3', tests)


def brute_sagemaker_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sagemaker.html
    '''
    print("### Enumerating  Amazon SageMaker Service Permissions ###")
    tests = [('listEndpointConfigs', 'list_endpoint_configs', (), {}),
             ('ListEndpoints', 'list_endpoints', (), {}),
             ('ListModels', 'list_models', (), {}),
             ('ListNotebookInstanceLifecycleConfigs', 'list_notebook_instance_lifecycle_configs', (), {}),
             ('ListNotebookInstances', 'list_notebook_instances', (), {}),
             ('ListTrainingJobs', 'list_training_jobs', (), {}), ]
    return generic_permission_bruteforcer('sagemaker', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/sagemaker-runtime.html
# no functions


def brute_sdb_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sdb.html
    '''
    print("### Enumerating SimpleDB Permissions ###")
    tests = [('ListDomains', 'list_domains', (), {}), ]
    return generic_permission_bruteforcer('sdb', tests)


def brute_secretsmanager_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/secretsmanager.html
    '''
    print("### Enumerating AWS Secrets Manager Permissions ###")
    tests = [('ListSecrets', 'list_secrets', (), {}), ]
    return generic_permission_bruteforcer('secretsmanager', tests)


def brute_serverlessrepo_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/serverlessrepo.html
    '''
    print("### Enumerating AWS ServerlessApplicationRepository Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}), ]
    return generic_permission_bruteforcer('serverlessrepo', tests)


def brute_servicecatalog_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/servicecatalog.html
    '''
    print("### Enumerating Service Catalog Permissions ###")
    tests = [('ListPortfolios', 'list_portfolios', (), {}),
             ('ListRecordHistory', 'list_record_history', (), {}),
             ('ListAcceptedPortfolioShares', 'list_accepted_portfolio_shares', (), {}), ]
    return generic_permission_bruteforcer('servicecatalog', tests)


def brute_servicediscovery_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/servicediscovery.html
    '''
    print("### Enumerating Amazon Route 53 Auto Naming (ServiceDiscovery) Permissions ###")
    tests = [('ListServices', 'list_services', (), {}), ]
    return generic_permission_bruteforcer('servicediscovery', tests)


def brute_ses_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ses.html
    '''
    print("### Enumerating Simple Email Service (SES) Permissions ###")
    tests = [('ListIdentities', 'list_identities', (), {}),
             ('GetSendStatistics', 'get_send_statistics', (), {}),
             ('ListConfigurationSets', 'list_configuration_sets', (), {}), ]
    return generic_permission_bruteforcer('ses', tests)


def brute_shield_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/shield.html
    '''
    print("### Enumerating Shield Permissions ###")
    tests = [('ListAttacks', 'list_attacks', (), {}),
             ('ListProtections', 'list_protections', (), {}),
             ('DescribeSubscription', 'describe_subscription', (), {}), ]
    return generic_permission_bruteforcer('shield', tests)


def brute_sms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sms.html
    '''
    print("### Enumerating Server Migration Service (SMS) Permissions ###")
    tests = [('GetReplicationJobs', 'get_replication_jobs', (), {}),
             ('GetServers', 'get_servers', (), {}), ]
    return generic_permission_bruteforcer('sms', tests)


def brute_snowball_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/snowball.html
    '''
    print("### Enumerating Snowball Permissions ###")
    tests = [('GetSnowballUsage', 'get_snowball_usage', (), {}),
             ('ListClusters', 'list_clusters', (), {}),
             ('ListJobs', 'list_jobs', (), {}), ]
    return generic_permission_bruteforcer('snowball', tests)


def brute_sns_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sns.html
    '''
    print("### Enumerating Simple Notification Service (SNS) Permissions ###")
    tests = [('ListPlatformApplications', 'list_platform_applications', (), {}),
             ('ListPhoneNumbersOptedOut', 'list_phone_numbers_opted_out', (), {}),
             ('ListSubscriptions', 'list_subscriptions', (), {}),
             ('ListTopics', 'list_topics', (), {}),
             ('GetSmsAttributes', 'get_sms_attributes', (), {}), ]
    return generic_permission_bruteforcer('sns', tests)


def brute_sqs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sqs.html
    '''
    print("### Enumerating Simple Queue Service (SQS) Permissions ###")
    tests = [('ListQueues', 'list_queues', (), {}), ]
    return generic_permission_bruteforcer('sqs', tests)


def brute_ssm_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/ssm.html
    '''
    print("### Enumerating Amazon Simple Systems Manager (SSM) Permissions ###")
    tests = [('DescribeActivations', 'describe_activations', (), {}),
             # ('DescribeAssociation', 'describe_association', (), {}),
             ('ListDocuments', 'list_documents', (), {}),
             ('ListResourceComplianceSummaries', 'list_resource_compliance_summaries', (), {}), ]
    return generic_permission_bruteforcer('ssm', tests)


def brute_stepfunctions_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/stepfunctions.html
    '''
    print("### Enumerating Step Functions (SFN) Permissions ###")
    tests = [('ListActivities', 'list_activities', (), {}), ]
    return generic_permission_bruteforcer('stepfunctions', tests)


def brute_storagegateway_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/storagegateway.html
    '''
    print("### Enumerating AWS Storage Gateway Permissions ###")
    tests = [('ListGateways', 'list_gateways', (), {}),
             ('ListFileShares', 'list_file_shares', (), {}),
             ('ListVolumes', 'list_volumes', (), {}),
             ('ListTapes', 'list_tapes', (), {}), ]
    return generic_permission_bruteforcer('storagegateway', tests)


def brute_sts_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sts.html
    '''
    print("### Enumerating Security Token Service (STS) Permissions ###")
    tests = [('GetCallerIdentity', 'get_caller_identity', (), {}), ]
    return generic_permission_bruteforcer('sts', tests)


def brute_support_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/support.html
    '''
    print("### Enumerating AWS Support Permissions ###")
    tests = [('DescribeCases', 'describe_cases', (), {}),
             ('DescribeServices', 'describe_services', (), {}), ]
    return generic_permission_bruteforcer('support', tests)


def brute_swf_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/swf.html
    '''
    print("### Enumerating Amazon Simple Workflow Service (SWF) Permissions ###")
    tests = [('ListDomains', 'list_domains', (), {'registrationStatus': 'REGISTERED'}), ]
    return generic_permission_bruteforcer('swf', tests)


def brute_transcribe_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/transcribe.html
    '''
    print("### Enumerating Amazon Transcribe Service Permissions ###")
    tests = [('ListTranscriptionJobs', 'list_transcription_jobs', (), {}),
             ('ListVocabularies', 'list_vocabularies', (), {}), ]
    return generic_permission_bruteforcer('transcribe', tests)


def brute_translate_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/translate.html
    '''
    print("### Enumerating  Amazon Translate Permissions ###")
    tests = [('TranslateText', 'translate_text', (), {'Text': 'secure your shit', 'SourceLanguageCode': 'en', 'TargetLanguageCode': 'es'}), ]
    return generic_permission_bruteforcer('translate', tests)


def brute_waf_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/waf.html
    '''
    print("### Enumerating AWS WAF Permissions ###")
    tests = [('ListRules', 'list_rules', (), {}),
             ('ListRuleGroups', 'list_rule_groups', (), {}),
             # ('ListActivatedRulesInRuleGroup', 'list_activated_rules_in_rule_group', (), {}),
             ('ListIpSets', 'list_ip_sets', (), {}), ]
    return generic_permission_bruteforcer('waf', tests)


def brute_waf_regional_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/waf-regional.html
    '''
    print("### Enumerating AWS WAF Regional Permissions ###")
    tests = [('ListRules', 'list_rules', (), {}),
             ('ListRuleGroups', 'list_rule_groups', (), {}),
             # ('ListActivatedRulesInRuleGroup', 'list_activated_rules_in_rule_group', (), {}),
             ('ListIpSets', 'list_ip_sets', (), {}), ]
    return generic_permission_bruteforcer('waf-regional', tests)


def brute_workdocs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/workdocs.html
    '''
    print("### Enumerating Amazon WorkDocs Permissions ###")
    tests = [('DescribeUsers', 'describe_users', (), {}), ]
    return generic_permission_bruteforcer('workdocs', tests)


def brute_workmail_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/workmail.html
    '''
    print("### Enumerating Amazon WorkMail Permissions ###")
    tests = [('ListOrganizations', 'list_organizations', (), {}), ]
    return generic_permission_bruteforcer('workmail', tests)


def brute_workspaces_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/workspaces.html
    '''
    print("### Enumerating WorkSpaces Permissions ###")
    tests = [('DescribeWorkspaceBundles', 'describe_workspace_bundles', (), {}),
             ('DescribeWorkspaceDirectories', 'describe_workspace_directories', (), {}),
             ('DescribeWorkspaces', 'describe_workspaces', (), {}),
             ('DescribeWorkspacesConnectionStatus', 'describe_workspaces_connection_status', (), {}), ]
    return generic_permission_bruteforcer('workspaces', tests)


def brute_xray_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/xray.html
    NO functions that dont take any arguements. GetTraceSummaries requires start/end times, We can
    probably programatically  add these - need to see what the service actually does
    '''
    print("### Enumerating X-Ray Permissions ###")
    tests = [('GetTraceSummaries', 'get_trace_summaries', (), {}), ]
    return generic_permission_bruteforcer('xray', tests)

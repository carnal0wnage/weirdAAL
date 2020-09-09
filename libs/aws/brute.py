'''
Brute functions for WeirdAAL

This is the main brute library so that we can get an idea what services a particular
key has access to. We do this by asking if we have permission on as many services &
subfunctions as we can. Printed to screen and logged to db.

https://docs.aws.amazon.com/general/latest/gr/aws-service-information.html

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


def brute_amplify_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/amplify.html
    '''
    print("### Enumerating AWS Amplify Permissions ###")
    tests = [('ListApps', 'list_apps', (), {}, ), ]
    return generic_permission_bruteforcer('amplify', tests)


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


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigatewaymanagementapi.html
#  no functions


def brute_apigatewayv2_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigatewayv2.html
    '''
    print("### Enumerating AmazonApiGatewayV2 Permissions ###")
    tests = [('GetApis', 'get_apis', (), {}, ), ]
    return generic_permission_bruteforcer('apigatewayv2', tests)


def brute_appconfig_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/appconfig.html
    '''
    print("### Enumerating Amazon AppConfig Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}, ), ]
    return generic_permission_bruteforcer('appconfig', tests)


#  http://boto3.readthedocs.io/en/latest/reference/services/application-autoscaling.html
#  not seeing any functions that dont take args


def brute_applicationinsights_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/application-insights.html
    '''
    print("### Enumerating Amazon CloudWatch Application Insights Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}, ), ]
    return generic_permission_bruteforcer('application-insights', tests)


def brute_appmesh_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/appmesh.html
    '''
    print("### Enumerating AWS App Mesh Permissions ###")
    tests = [('ListMeshes', 'list_meshes', (), {}, ), ]
    return generic_permission_bruteforcer('appmesh', tests)


def brute_appstream_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/appstream.html
    '''
    print("### Enumerating APPStream Permissions ###")
    tests = [('DescribeFleets', 'describe_fleets', (), {}, ),
             ('DescribeImages', 'describe_images', (), {}, ),
             ('DescribeStacks', 'describe_stacks', (), {}, ), ]
    return generic_permission_bruteforcer('appstream', tests)


#  http://boto3.readthedocs.io/en/latest/reference/services/appsync.html
#  not seeing any functions that dont take args


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


def brute_backup_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html
    '''
    print("### Enumerating AWS Backup Permissions ###")
    tests = [('ListBackupJobs', 'list_backup_jobs', (), {}, ),
             ('ListBackupPlans', 'list_backup_plans', (), {}, ),
             ('ListBackupVaults', 'list_backup_vaults', (), {}, ), ]
    return generic_permission_bruteforcer('backup', tests)


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

#  http://boto3.readthedocs.io/en/latest/reference/services/ce.html
#  TODO
#  http://boto3.readthedocs.io/en/latest/reference/services/ce.html#CostExplorer.Client.get_cost_and_usage
#  should work we just need to generate start and end times each run


def brute_chime_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/chime.html
    '''
    print("### Enumerating Chime Permissions ###")
    tests = [('ListAccounts', 'list_accounts', (), {}, ), 
             ('GetGlobalSettings', 'get_global_settings', (), {}, ), ]
    return generic_permission_bruteforcer('chime', tests)


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


def brute_codegurureviewer_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codeguru-reviewer.html
    '''
    print("### Enumerating Amazon CodeGuru Reviewer Permissions ###")
    tests = [('ListCodeReviews', 'list_code_reviews', (), {'Type':'PullRequest'}, ), 
             ('ListCodeReviews', 'list_code_reviews', (), {'Type':'RepositoryAnalysis'}, ), ]
    return generic_permission_bruteforcer('codeguru-reviewer', tests)


def brute_codeguruprofiler_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codeguruprofiler.html
    '''
    print("### Enumerating Amazon CodeGuru Profiler Permissions ###")
    tests = [('ListProfilingGroups', 'list_profiling_groups', (), {}, ), ]
    return generic_permission_bruteforcer('codeguruprofiler', tests)


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
             ('ListUserProfiles', 'list_user_profiles', (), {}, ), ]
    return generic_permission_bruteforcer('codestar', tests)


def brute_codestarconnections_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codestar-connections.html
    '''
    print("### Enumerating AWS CodeStar Connections Permissions ###")
    tests = [('ListConnections', 'list_connections', (), {}, ),
             #('ListHosts', 'list_hosts', (), {}, ), 
             ]
    return generic_permission_bruteforcer('codestar-connections', tests)


def brute_codestarnotifications_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/codestar-notifications.html
    '''
    print("### Enumerating AWS CodeStar Notifications Permissions ###")
    tests = [('ListNotificationRules', 'list_notification_rules', (), {}, ),
             ('ListTargets', 'list_targets', (), {}, ), 
             ]
    return generic_permission_bruteforcer('codestar-notifications', tests)


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


def brute_comprehendmedical_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehendmedical.html
    '''
    print("### Enumerating AWS Comprehend Medical Permissions ###")
    tests = [('ListEntitiesDetectionv2Jobs', 'list_entities_detection_v2_jobs', (), {}, ), 
             ('ListIcd10cmInferenceJobs', 'list_icd10_cm_inference_jobs', (), {}, ),
             ('listPhiDetectionJobs', 'list_phi_detection_jobs', (), {}, ),
             ('listRxNormInferenceJobs', 'list_rx_norm_inference_jobs', (), {}, ), ]
    return generic_permission_bruteforcer('comprehendmedical', tests)


def brute_computeoptimizer_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/compute-optimizer.html
    '''
    print("### Enumerating AWS Compute Optimizer Permissions ###")
    tests = [('GetRecommendationSummaries', 'get_recommendation_summaries', (), {}, ), ]
    return generic_permission_bruteforcer('compute-optimizer', tests)


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

#  http://boto3.readthedocs.io/en/latest/reference/services/connect.html
#  no functions

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/connectparticipant.html
#  no functions


def brute_costandusagereportservice_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/cur.html
    '''
    print("### Enumerating CostandUsageReportService Permissions ###")
    tests = [('DescribeReportDefinitions', 'describe_report_definitions', (), {}, ), ]
    return generic_permission_bruteforcer('cur', tests)


def brute_dataexchange_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dataexchange.html
    '''
    print("### Enumerating AWS Data Exchange Permissions ###")
    tests = [('ListDataSets', 'list_data_sets', (), {}, ), 
             ('ListJobs', 'list_jobs', (), {}, ), ] 
    return generic_permission_bruteforcer('dataexchange', tests)


def brute_datapipeline_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/datapipeline.html
    '''
    print("### Enumerating DataPipeline Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}, ), ]
    return generic_permission_bruteforcer('datapipeline', tests)


def brute_datasync_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/datasync.html
    '''
    print("### Enumerating  AWS DataSync Permissions ###")
    tests = [('ListAgents', 'list_agents', (), {}, ), 
             ('ListTasks', 'list_tasks', (), {}, ), ] 
    return generic_permission_bruteforcer('datasync', tests)


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


def brute_detective_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/detective.html
    '''
    print("### Enumerating Amazon Detective Permissions ###")
    tests = [('ListGraphs', 'list_graphs', (), {}, ), ]
    return generic_permission_bruteforcer('detective', tests)


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


def brute_dlm_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dlm.html
    '''
    print("### Enumerating DatabaseMigrationService Permissions ###")
    tests = [('GetLifecyclePolicies', 'get_lifecycle_policies', (), {}, ), ]
    return generic_permission_bruteforcer('dlm', tests)


def brute_dms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/dms.html
    '''
    print("### Enumerating DatabaseMigrationService Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}, ),
             ('DescribeEvents', 'describe_events', (), {}, ),
             ('DescribeConnections', 'describe_connections', (), {}, ), ]
    return generic_permission_bruteforcer('dms', tests)


def brute_docdb_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/docdb.html
    '''
    print("### Enumerating DocumentDB with MongoDB Permissions ###")
    tests = [('DescribeDBClusters', 'describe_db_clusters', (), {}, ),
             ('DescribeDBInstances', 'describe_db_instances', (), {}, ),
             ('DescribeDBEngineVersions', 'describe_db_engine_versions', (), {}, ), ]
    return generic_permission_bruteforcer('docdb', tests)


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


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs.html
#  no functions that dont require a SnapshotId 


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


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2-instance-connect.html
#  no functions


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


def brute_eks_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html
    '''
    print("### Enumerating Amazon Elastic Kubernetes Service (EKS) Permissions ###")
    tests = [('ListClusters', 'list_clusters', (), {}), ]
    return generic_permission_bruteforcer('eks', tests)


def brute_elasticinference_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elastic-inference.html
    '''
    print("### Enumerating Amazon Elastic Inference Permissions ###")
    tests = [('DescribeAccelerators', 'describe_accelerators', (), {}), ]
    return generic_permission_bruteforcer('elastic-inference', tests)


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


def brute_forecast_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/forecast.html
    '''
    print("### Enumerating Amazon Forecast Permissions ###")
    tests = [('ListDatasets', 'list_datasets', (), {}),
             ('ListForecasts', 'list_forecasts', (), {}), 
             ('ListPredictors', 'list_predictors', (), {}), ]
    return generic_permission_bruteforcer('forecast', tests)


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/forecastquery.html
#  no functions


def brute_frauddetector_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/frauddetector.html
    '''
    print("### Enumerating Amazon Fraud Detector Permissions ###")
    tests = [('GetDetectors', 'get_detectors', (), {}), ]
    return generic_permission_bruteforcer('frauddetector', tests)


def brute_fsx_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/fsx.html
    '''
    print("### Enumerating FSx Permissions ###")
    tests = [('DescribeBackups', 'describe_backups', (), {}),
             ('DescribeDataRepositoryTasks', 'describe_data_repository_tasks', (), {}),
             ('DescribeFileSystems', 'describe_file_systems', (), {}), ]
    return generic_permission_bruteforcer('fsx', tests)


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


def brute_globalaccelerator_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/globalaccelerator.html
    '''
    print("### Enumerating global Accelerator Permissions ###")
    tests = [('ListAccelerators', 'list_accelerators', (), {}), ]
    return generic_permission_bruteforcer_region('globalaccelerator', tests, 'us-west-2')


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


def brute_groundstation_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/groundstation.html
    '''
    print("### Enumerating Groundstation Permissions ###")
    tests = [('ListConfigs', 'list_configs', (), {}),
             ('ListGroundStations', 'list_ground_stations', (), {}),
             ('ListSatellites', 'list_satellites', (), {}), ]
    return generic_permission_bruteforcer_region('groundstation', tests, 'us-west-2')

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


def brute_imagebuilder_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/imagebuilder.html
    '''
    print("### Enumerating Image Builder Permissions ###")
    tests = [('ListComponents', 'list_components', (), {}), 
             ('ListDistributionConfigurations', 'list_distribution_configurations', (), {}),
             ('ListImagePipelines', 'list_image_pipelines', (), {}),
             ('ListImageRecipes', 'list_image_recipes', (), {}),
             ('ListImages', 'list_images', (), {}),
             ('ListInfrastructureConfigurations', 'list_infrastructure_configurations', (), {}), ]
    return generic_permission_bruteforcer('imagebuilder', tests)


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


def brute_iot1clickdevices_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iot1click-devices.html
    https://docs.aws.amazon.com/general/latest/gr/1click.html
    '''
    print("### Enumerating AWS IoT 1-Click Devices Service Permissions ###")
    tests = [('ListDevices', 'list_devices', (), {}), ]
    return generic_permission_bruteforcer_region('iot1click-devices', tests, 'us-west-2')


def brute_iot1clickprojects_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iot1click-projects.html
    '''
    print("### Enumerating AWS IoT 1-Click Projects Service Permissions ###")
    tests = [('ListProjects', 'list_projects', (), {}), ]
    return generic_permission_bruteforcer_region('iot1click-projects', tests, 'us-west-2')


def brute_iotanalytics_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotanalytics.html
    '''
    print("### Enumerating AWS IoT 1-Click Projects Service Permissions ###")
    tests = [('ListChannels', 'list_channels', (), {}), 
             ('ListDatasets', 'list_datasets', (), {}),
             ('ListDatastores', 'list_datastores', (), {}),
             ('ListPipelines', 'list_pipelines', (), {}), ]
    return generic_permission_bruteforcer_region('iotanalytics', tests, 'us-west-2')


def brute_iotevents_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotevents.html
    '''
    print("### Enumerating AWS IoT Events Service Permissions ###")
    tests = [('ListDetectorModels', 'list_detector_models', (), {}), 
             ('ListInputs', 'list_inputs', (), {}), ]
    return generic_permission_bruteforcer_region('iotevents', tests, 'us-west-2')

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotevents-data.html
#  need detectorID


def brute_iotsecuretunneling_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotsecuretunneling.html
    '''
    print("### Enumerating AWS  IoT Secure Tunneling Permissions ###")
    tests = [('ListTunnels', 'list_tunnels', (), {}), ]
    return generic_permission_bruteforcer_region('iotsecuretunneling', tests, 'us-west-2')


def brute_iotsitewise_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotsitewise.html
    '''
    print("### Enumerating AWS IoT Sitewise Permissions ###")
    tests = [('ListAssets', 'list_assets', (), {}), 
             ('ListPortals', 'list_portals', (), {}), 
             ('ListGateways', 'list_gateways', (), {}), ]
    return generic_permission_bruteforcer_region('iotsitewise', tests, 'us-west-2')

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iotthingsgraph.html
#  no functions


def brute_kafka_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html
    '''
    print("### Enumerating Kafka Permissions ###")
    tests = [('ListClusters', 'list_clusters', (), {}), ]
    return generic_permission_bruteforcer('kafka', tests)


def brute_kendra_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kendra.html
    '''
    print("### Enumerating Kendra Frontend Service Permissions ###")
    tests = [('ListIndices', 'list_indices', (), {}), ]
    return generic_permission_bruteforcer('kendra', tests)


def brute_kinesis_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kinesis.html
    '''
    print("### Enumerating Kinesis Permissions ###")
    tests = [('ListStreams', 'list_streams', (), {}), ]
    return generic_permission_bruteforcer('kinesis', tests)

#  http://boto3.readthedocs.io/en/latest/reference/services/kinesis-video-archived-media.html
#  NO functions to call without data

#  http://boto3.readthedocs.io/en/latest/reference/services/kinesis-video-media.html
#  NO functions to call without data

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesis-video-signaling.html
#  NO functions to call without data

def brute_kinesisanalytics_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/kinesisanalytics.html
    '''
    print("### Enumerating Kinesis Analytics Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}), ]
    return generic_permission_bruteforcer('kinesisanalytics', tests)


def brute_kinesisanalyticsv2_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesisanalyticsv2.html
    '''
    print("### Enumerating Kinesis Analytics v2 Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}), ]
    return generic_permission_bruteforcer('kinesisanalyticsv2', tests)


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


def brute_lakeformation_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lakeformation.html
    '''
    print("### Enumerating Lake Formation Permissions ###")
    tests = [('ListPermissions', 'list_permissions', (), {}),
             ('ListResources', 'list_resources', (), {}), ]
    return generic_permission_bruteforcer('lakeformation', tests)


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


def brute_licensemanager_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/license-manager.html
    '''
    print("### Enumerating License Manager Permissions ###")
    tests = [('ListLicenseConfigurations', 'list_license_configurations', (), {}), ]
    return generic_permission_bruteforcer('license-manager', tests)


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


def brute_macie_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/macie.html
    '''
    print("### Enumerating Macie Permissions ###")
    tests = [('ListMemberAccounts', 'list_member_accounts', (), {}),
             ('ListS3Resources', 'list_s3_resources', (), {}), ]
    return generic_permission_bruteforcer('macie', tests)


def brute_macie2_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/macie2.html
    '''
    print("### Enumerating Macie2 Permissions ###")
    tests = [('DescribeBuckets', 'describe_buckets', (), {}),
             ('ListFindings', 'list_findings', (), {}), 
             ('Listmembers', 'list_members', (), {}),]
    return generic_permission_bruteforcer('macie2', tests)

def brute_managedblockchain_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/managedblockchain.html
    '''
    print("### Enumerating Managed Blockchain Permissions ###")
    tests = [('ListNetworks', 'list_networks', (), {}), ]
    return generic_permission_bruteforcer('managedblockchain', tests)


def brute_marketplacecatalog_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/marketplace-catalog.html
    needs an entity type for list_entities ??
    '''
    print("### Enumerating Machine Learning Permissions ###")
    tests = [('ListEntities', 'list_entities', (), {}), ]
    return generic_permission_bruteforcer('marketplace-catalog', tests)

# http://boto3.readthedocs.io/en/latest/reference/services/marketplace-entitlement.html
# NO functions to call without arguments

# http://boto3.readthedocs.io/en/latest/reference/services/marketplacecommerceanalytics.html
# NO functions to call without arguments


def brute_mediaconnect_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediaconnect.html
    '''
    print("### Enumerating MediaConnect Permissions ###")
    tests = [('ListEntitlements', 'list_entitlements', (), {}),
             ('ListFlows', 'list_flows', (), {}), ]
    return generic_permission_bruteforcer('mediaconnect', tests)


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


def brute_mediapackagevod_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediapackage-vod.html
    '''
    print("### Enumerating MediaPackage VOD Permissions ###")
    tests = [('ListAssets', 'list_assets', (), {}), 
             ('ListPackagingGroups', 'list_packaging_groups', (), {}), ]
    return generic_permission_bruteforcer('mediapackage-vod', tests)


def brute_mediastore_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediastore.html
    '''
    print("### Enumerating AWS Elemental MediaStore Permissions ###")
    tests = [('ListContainers', 'list_containers', (), {}), ]
    return generic_permission_bruteforcer_region('mediastore', tests, 'us-west-2')


def brute_mediastore_data_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mediastore-data.html
    Could not connect to the endpoint URL: "https://data.mediastore.us-east-1.amazonaws.com/"
    https://docs.aws.amazon.com/general/latest/gr/mediastore.html

    Update Sep2020 - i cant find an endpoint to connect to tried us-east-1/us-west-2
    will comment this out in recon.py
    '''
    print("### Enumerating AWS Elemental MediaStore Data Permissions ###")
    tests = [('ListItems', 'list_items', (), {}), ]
    return generic_permission_bruteforcer_region('mediastore-data', tests, 'us-west-2')


def brute_mediatailor_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mediatailor.html
    '''
    print("### Enumerating MediaTailor Permissions ###")
    tests = [('ListPlaybackConfigurations', 'list_playback_configurations', (), {}), ]
    return generic_permission_bruteforcer('mediatailor', tests)


#  http://boto3.readthedocs.io/en/latest/reference/services/meteringmarketplace.html
#  NO functions to call without arguments


def brute_mgh_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/mgh.html
    '''
    print("### Enumerating AWS Migration Hub Permissions ###")
    tests = [('ListMigrationTasks', 'list_migration_tasks', (), {}),
             ('ListProgressUpdateStreams', 'list_progress_update_streams', (), {}), ]
    return generic_permission_bruteforcer_region('mgh', tests, 'us-west-2')


def brute_migrationhubconfig_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/migrationhub-config.html
    '''
    print("### Enumerating migrationhub-config Permissions ###")
    tests = [('DescribeHomeRegionControls', 'describe_home_region_controls', (), {}), ]
    return generic_permission_bruteforcer('migrationhub-config', tests)


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


def brute_neptune_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/neptune.html
    '''
    print("### Enumerating Neptune Permissions ###")
    tests = [('DescribeDBClusters', 'describe_db_clusters', (), {}), 
             ('DescribeDBEngineVersions', 'describe_db_engine_versions', (), {}),
             ('DescribeDBInstances', 'describe_db_instances', (), {}),
             ('DescribeEvents', 'describe_events', (), {}), ]
    return generic_permission_bruteforcer('neptune', tests)


def brute_networkmanager_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/networkmanager.html
    Other functions needs the Global Network ID
    https://docs.aws.amazon.com/general/latest/gr/network_manager.html
    '''
    print("### Enumerating Network Manager Permissions ###")
    tests = [('DescribeGlobalNetworks', 'describe_global_networks', (), {}), ]
    return generic_permission_bruteforcer_region('networkmanager', tests, 'us-west-2')


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


def brute_outposts_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/outposts.html
    '''
    print("### Enumerating Outposts Service Permissions ###")
    tests = [('ListOutposts', 'list_outposts', (), {}), 
             ('ListSites', 'list_sites', (), {}),]
    return generic_permission_bruteforcer('outposts', tests)


def brute_personalize_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/personalize.html
    '''
    print("### Enumerating Personalize Service Permissions ###")
    tests = [('ListCampaigns', 'list_campaigns', (), {}), 
             ('ListDatasets', 'list_datasets', (), {}), 
             ('ListRecipes', 'list_recipes', (), {}),]
    return generic_permission_bruteforcer('personalize', tests)

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/personalize-events.html
#  No functions


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/personalize-runtime.html
#  No functions


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/pi.html
#  No functions

def brute_pinpoint_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/pinpoint.html
    '''
    print("### Enumerating Pinpoint Service Permissions ###")
    tests = [('GetApps', 'get_apps', (), {}), ]
    return generic_permission_bruteforcer('pinpoint', tests)


def brute_pinpoint_email_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/pinpoint-email.html
    '''
    print("### Enumerating Pinpoint Email Service Permissions ###")
    tests = [('GetAccount', 'get_account', (), {}),
             ('ListConfigurationSets', 'list_configuration_sets', (), {}),
             ('ListEmailIdentities', 'list_email_identities', (), {}), ]
    return generic_permission_bruteforcer('pinpoint-email', tests)

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/pinpoint-sms-voice.html
#  No functions


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


def brute_qldb_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/qldb.html
    '''
    print("### Enumerating AWS QLDB Permissions ###")
    tests = [('ListLedgers', 'list_ledgers', (), {}), 
             ('ListJournalS3Exports', 'list_journal_s3_exports', (), {}),]
    return generic_permission_bruteforcer('qldb', tests)


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/qldb-session.html
#  No functions


def brute_quicksight_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/quicksight.html
    '''
    print("### Enumerating AWS Quicksight Permissions ###")
    account_id = get_accountid()
    tests = [('ListDashboards', 'list_dashboards', (), {'AwsAccountId': account_id}), 
             ('ListDataSets', 'list_data_sets', (), {'AwsAccountId': account_id}),
             ('ListUsers', 'list_users', (), {'AwsAccountId': account_id, 'Namespace':'default'}),]
    return generic_permission_bruteforcer('quicksight', tests)


def brute_ram_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ram.html
    '''
    print("### Enumerating AWS Ram Permissions ###")
    tests = [('ListPermissions', 'list_permissions', (), {}), 
             ('ListPrincipals', 'list_principals', (), {'resourceOwner':'SELF'}),
             ('ListPrincipals', 'list_principals', (), {'resourceOwner':'OTHER-ACCOUNTS'}),
             ('ListResources', 'list_resources', (), {'resourceOwner':'SELF'}),
             ('ListResources', 'list_resources', (), {'resourceOwner':'OTHER-ACCOUNTS'}),]
    return generic_permission_bruteforcer('ram', tests)


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


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds-data.html
#  No Functions


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


def brute_robomaker_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/robomaker.html
    '''
    print("### Enumerating AWS Robomaker ###")
    tests = [('ListFleets', 'list_fleets', (), {}), 
             ('ListRobots', 'list_robots', (), {}),
             ('ListSimulationApplications', 'list_simulation_applications', (), {}),
             ('ListSimulationJobs', 'list_simulation_jobs', (), {}),]
    return generic_permission_bruteforcer('robomaker', tests)

def brute_route53_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/route53.html
    '''
    print("### Enumerating AWS Route53 Permissions ###")
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


def brute_route53resolver_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53resolver.html
    '''
    print("### Enumerating Route53Resolver Permissions ###")
    tests = [('ListResolverEndpoints', 'list_resolver_endpoints', (), {}),
             ('ListResolverRules', 'list_resolver_rules', (), {}), ]
    return generic_permission_bruteforcer('route53resolver', tests)


def brute_s3_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/s3.html
    '''
    print("### Enumerating S3 Permissions ###")
    tests = [('ListBuckets', 'list_buckets', (), {}), ]
    return generic_permission_bruteforcer('s3', tests)


def brute_s3control_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3control.html
    May 2020 - this returns yes but doesnt ever return results when digging further - currently
    commented out
    '''
    print("### Enumerating AWS S3 Control Permissions ###")
    account_id = get_accountid()
    tests = [('ListAccessPoints', 'list_access_points', (), {'AccountId': account_id}),
             ('ListJobs', 'list_jobs', (), {'AccountId': account_id}), ]
    return generic_permission_bruteforcer('s3control', tests)


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

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sagemaker-a2i-runtime.html
#  No functions


#  http://boto3.readthedocs.io/en/latest/reference/services/sagemaker-runtime.html
#  No functions


def brute_savingsplans_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/savingsplans.html
    '''
    print("### Enumerating AWS Savings Plans Permissions ###")
    tests = [('DescribeSavingsPlans', 'describe_savings_plans', (), {}), ]
    return generic_permission_bruteforcer('savingsplans', tests)


def brute_schemas_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/schemas.html
    '''
    print("### Enumerating AWS Schemas Permissions ###")
    tests = [('ListDiscoverers', 'list_discoverers', (), {}),
             ('ListRegistries', 'list_registries', (), {}), ]
    return generic_permission_bruteforcer('schemas', tests)


def brute_sdb_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sdb.html
    '''
    print("### Enumerating AWS SimpleDB Permissions ###")
    tests = [('ListDomains', 'list_domains', (), {}), ]
    return generic_permission_bruteforcer('sdb', tests)


def brute_secretsmanager_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/secretsmanager.html
    '''
    print("### Enumerating AWS Secrets Manager Permissions ###")
    tests = [('ListSecrets', 'list_secrets', (), {}), ]
    return generic_permission_bruteforcer('secretsmanager', tests)


def brute_securityhub_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html
    '''
    print("### Enumerating AWS SecurityHub Permissions ###")
    tests = [('DescribeHub', 'describe_hub', (), {}),
             ('DescribeProducts', 'describe_products', (), {}),
             ('DescribeStandards', 'describe_standards', (), {}),
             ('GetEnabledStandards', 'get_enabled_standards', (), {}),
             ('GetFindings', 'get_findings', (), {}),
             ('GetInsights', 'get_insights', (), {}),
             ('ListMembers', 'list_members', (), {}),
    ]
    return generic_permission_bruteforcer('securityhub', tests)


def brute_serverlessrepo_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/serverlessrepo.html
    '''
    print("### Enumerating AWS ServerlessApplicationRepository Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}), ]
    return generic_permission_bruteforcer('serverlessrepo', tests)


def brute_servicequotas_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/service-quotas.html
    '''
    print("### Enumerating AWS Service Quotas Permissions ###")
    tests = [('ListServices', 'list_services', (), {}), ]
    return generic_permission_bruteforcer('service-quotas', tests)


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


def brute_sesv2_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sesv2.html
    '''
    print("### Enumerating Simple Email Service (SESv2) Permissions ###")
    tests = [('GetAccount', 'get_account', (), {}),
             ('ListDedicatedIpPools', 'list_dedicated_ip_pools', (), {}),
             ('ListDeliverabilityTestReports', 'list_deliverability_test_reports', (), {}),
             ('ListEmailIdentities', 'list_email_identities', (), {}),
             ('ListConfigurationSets', 'list_configuration_sets', (), {}), ]
    return generic_permission_bruteforcer('sesv2', tests)


def brute_shield_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/shield.html
    '''
    print("### Enumerating Shield Permissions ###")
    tests = [('ListAttacks', 'list_attacks', (), {}),
             ('ListProtections', 'list_protections', (), {}),
             ('DescribeSubscription', 'describe_subscription', (), {}), ]
    return generic_permission_bruteforcer('shield', tests)


def brute_signer_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/signer.html
    '''
    print("### Enumerating Amazon Signer Permissions ###")
    tests = [('ListSigningJobs', 'list_signing_jobs', (), {}),
             ('ListSigningPlatforms', 'list_signing_platforms', (), {}), 
             ('ListSigningProfiles', 'list_signing_profiles', (), {}), ]
    return generic_permission_bruteforcer('signer', tests)


def brute_sms_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/sms.html
    '''
    print("### Enumerating Server Migration Service (SMS) Permissions ###")
    tests = [('GetReplicationJobs', 'get_replication_jobs', (), {}),
             ('GetServers', 'get_servers', (), {}), ]
    return generic_permission_bruteforcer('sms', tests)


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sms-voice.html
#  Deprecated 


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


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso.html
#  No Functions


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-oidc.html
#  No Functions

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


def brute_synthetics_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/synthetics.html
    '''
    print("### Enumerating Amazon Synthetics Permissions ###")
    tests = [('DescribeCanaries', 'describe_canaries', (), {}), ]
    return generic_permission_bruteforcer('synthetics', tests)

#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/textract.html
#  No functions - requires to pass a document


def brute_transcribe_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/transcribe.html
    '''
    print("### Enumerating Amazon Transcribe Service Permissions ###")
    tests = [('ListTranscriptionJobs', 'list_transcription_jobs', (), {}),
             ('ListVocabularies', 'list_vocabularies', (), {}), ]
    return generic_permission_bruteforcer('transcribe', tests)


def brute_transfer_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/transfer.html
    '''
    print("### Enumerating Amazon Transfer Family Permissions ###")
    tests = [('ListServers', 'list_servers', (), {}),]
    return generic_permission_bruteforcer('transfer', tests)


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


def brute_wafv2_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2.html
    '''
    print("### Enumerating AWS WAFv2 Permissions ###")
    tests = [('ListAvailableManagedRuleGroups', 'list_available_managed_rule_groups', (), {'Scope':'CLOUDFRONT',}),
             ('ListAvailableManagedRuleGroups', 'list_available_managed_rule_groups', (), {'Scope':'REGIONAL',}),
             ('ListRuleGroups', 'list_rule_groups', (), {'Scope':'CLOUDFRONT'}),
             ('ListRuleGroups', 'list_rule_groups', (), {'Scope':'REGIONAL'}),
             ('ListLoggingConfigurations', 'list_logging_configurations', (), {'Scope':'CLOUDFRONT',}),
             ('ListLoggingConfigurations', 'list_logging_configurations', (), {'Scope':'REGIONAL',}),
             ('ListIpSets', 'list_ip_sets', (), {'Scope':'CLOUDFRONT',}),
             ('ListIpSets', 'list_ip_sets', (), {'Scope':'REGIONAL',}), 
             ('ListWebACLs', 'list_web_acls', (), {'Scope':'CLOUDFRONT',}),
             ('ListWebACLs', 'list_web_acls', (), {'Scope':'REGIONAL',}),]
    return generic_permission_bruteforcer('wafv2', tests)


def brute_workdocs_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/workdocs.html
    '''
    print("### Enumerating Amazon WorkDocs Permissions ###")
    tests = [('DescribeUsers', 'describe_users', (), {}), ]
    return generic_permission_bruteforcer('workdocs', tests)


def brute_worklink_permissions():
    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/worklink.html
    '''
    print("### Enumerating Amazon WorkLink Permissions ###")
    tests = [('ListFleets', 'list_fleets', (), {}), ]
    return generic_permission_bruteforcer('worklink', tests)


def brute_workmail_permissions():
    '''
    http://boto3.readthedocs.io/en/latest/reference/services/workmail.html
    '''
    print("### Enumerating Amazon WorkMail Permissions ###")
    tests = [('ListOrganizations', 'list_organizations', (), {}), ]
    return generic_permission_bruteforcer('workmail', tests)


#  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workmailmessageflow.html
#  No functions


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

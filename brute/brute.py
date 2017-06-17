import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, service, tests):
    actions = []
    try:
        client = boto3.client(service, aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name='us-east-1')
    except Exception as e:
        print('Failed to connect: "{}"' .format(e.error_message))
        return actions
    
    actions = generic_method_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, service, tests)
    if actions:
        print ("\n[+] {} Actions allowed are [+]" .format(service))
        print (actions)
        print ("\n")
    else:
        print ("\n[-] No {} actions allowed [-]" .format(service))
        print ("\n")

    return actions

def generic_method_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, service, tests):
    actions = []
    client = boto3.client(service, aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name='us-east-1')
    for api_action, method_name, args, kwargs in tests:
        try:
            method = getattr(client, method_name)
            method(*args, **kwargs)
            #print method --wont return anything on dryrun
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                print('{} IS allowed' .format(api_action))
                actions.append(api_action)
            else:
                print e
                continue 
        else:
            print('{} IS allowed' .format(api_action))
            actions.append(api_action)
    return actions

#http://boto3.readthedocs.io/en/latest/reference/services/acm.html
def brute_acm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating ACM Permissions ###")
    tests = [('ListCertificates', 'list_certificates', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'acm', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/apigateway.html
def brute_apigateway_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating APIGateway Permissions ###")
    tests = [('GetAccount', 'get_account', (), {}, ), 
             ('GetApiKeys', 'get_api_keys', (), {}, ), 
             ('GetClientCertificates', 'get_client_certificates', (), {}, ),
             ('GetDomainNames', 'get_domain_names', (), {}, ),
             ('GetRestApis', 'get_rest_apis', (), {}, ), 
             ('GetSdkTypes', 'get_sdk_types', (), {}, ), 
             ('GetUsagePlans', 'get_usage_plans', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'apigateway', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/appstream.html
def brute_appstream_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating APPStream Permissions ###")
    tests = [('DescribeFleets', 'describe_fleets', (), {}, ),
             ('DescribeImages', 'describe_images', (), {}, ), 
             ('DescribeStacks', 'describe_stacks', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'appstream', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/athena.html
def brute_athena_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Athena Permissions ###")
    tests = [('ListNamedQueries', 'list_named_queries', (), {}, ),
             ('ListQueryExecutions', 'list_query_executions', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'athena', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/autoscaling.html
def brute_autoscaling_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Autoscaling Permissions ###")
    tests = [('DescribeAccountLimits', 'describe_account_limits', (), {}, ),
             ('DescribeAdjustmentTypes', 'describe_adjustment_types', (), {}, ),
             ('DescribeAutoScalingInstances', 'describe_auto_scaling_instances', (), {}, ),
             ('DescribeAutoScalingGroups', 'describe_auto_scaling_groups', (), {}),
             ('DescribeLaunchConfigurations', 'describe_launch_configurations', (), {}),
             ('DescribeScheduledActions', 'describe_scheduled_actions', (), {}),
             ('DescribeTags', 'describe_tags', (), {}, ),
             ('DescribeTerminationPolicyTypes', 'describe_termination_policy_types', (), {}, ),
             ('DescribePolicies', 'describe_policies', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'autoscaling', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/batch.html
def brute_batch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Batch Permissions ###")
    tests = [('DescribeComputeEnvironments', 'describe_compute_environments', (), {}, ),
             ('DescribeJobDefinitions', 'describe_job_definitions', (), {}, ),  
             ('DescribeJobQueues', 'describe_job_queues', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'batch', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/budgets.html
# TODO REQUIRES ACCOUNT NUMBER 12 digits - should really pull this from the key we are trying
def brute_budgets_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Budgets Permissions ###")
    tests = [('DescribeBudgets', 'describe_budgets', (), {'AccountId':'123456789123'}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'budgets', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudformation.html
def brute_cloudformation_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CLoudFormation Permissions ###")
    tests = [('ListStacks', 'list_stacks', (), {} ),
             ('DescribeStacks', 'describe_stacks', (), {} ), 
             ('DescribeStackEvents', 'describe_stack_events', (), {} ), 
             ('DescribeStackResources', 'describe_stack_resources', (), {} ),
             ('ListExports', 'list_exports', (), {} ),
             ('DescribeAccountLimits', 'describe_account_limits', (), {} ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudformation', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudfront.html
def brute_cloudfront_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CLoudFront Permissions ###")
    tests = [('ListDistributions', 'list_distributions', (), {}), 
             ('ListCloudFrontOriginAcessIdentities', 'list_cloud_front_origin_access_identities', (), {}),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudfront', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudhsm.html
def brute_cloudhsm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CloudHSM Permissions ###")
    tests = [('DescribeHsm', 'describe_hsm', (), {}),
             ('ListHsms', 'list_hsms', (), {}),
             ('ListHapgs', 'list_hapgs', (), {}),
             ('DescribeLunaClient', 'describe_luna_client', (), {}),
             ('ListLunaClients', 'list_luna_clients', (), {}),
             ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudhsm', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudsearch.html
def brute_cloudsearch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CloudSearch Permissions ###")
    tests = [('DescribeDomains', 'describe_domains', (), {}, ), 
             ('ListDomainNames', 'list_domain_names', (), {}, ),

            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudsearch', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudtrail.html
def brute_cloudtrail_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CloudTrail Permissions ###")
    tests = [('DescribeTrails', 'describe_trails', (), {}, ), 
             ('ListPublicKeys', 'list_public_keys', (), {}, ),

            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudtrail', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cloudwatch.html
def brute_cloudwatch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CloudWatch Permissions ###")
    tests = [('ListMetrics', 'list_metrics', (), {}, ), 
             ('DescribeAlarmHistory', 'describe_alarm_history', (), {}, ),
             ('DescribeAlarms', 'describe_alarms', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cloudwatch', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/codebuild.html
def brute_codebuild_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CodeBuild Permissions ###")
    tests = [('ListBuilds', 'list_builds', (), {}, ), 
             ('ListCuratedEnvironmentImages', 'list_curated_environment_images', (), {}, ),  
             ('ListProjects', 'list_projects', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'codebuild', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/codecommit.html
def brute_codecommit_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CodeCommit Permissions ###")
    tests = [('ListRepositories', 'list_repositories', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'codecommit', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/codedeploy.html
def brute_codedeploy_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CodeDeploy Permissions ###")
    tests = [('ListApplications', 'list_applications', (), {}, ), 
             ('ListDeployments', 'list_deployments', (), {}, ), 
             ('ListDeploymentsConfigs', 'list_deployment_configs', (), {}, ), 
             #('ListGitHubAccountTokenNames', 'list_git_hub_account_token_names', (), {}, ), 
             ('ListOnPremisesInstances', 'list_on_premises_instances', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'codedeploy', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/codepipeline.html
def brute_codepipeline_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CodePipeline Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'codepipeline', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/codestar.html
def brute_codestar_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CodeStar Permissions ###")
    tests = [('ListProjects', 'list_projects', (), {}, ),  
             ('ListUerProfiles', 'list_user_profiles', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'codestar', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cognito-identity.html
def brute_cognitoidentity_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Cognito-Identity Permissions ###")
    tests = [('ListIdentityPools', 'list_identity_pools', (), {'MaxResults':1}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cognito-identity', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cognito-idp.html
def brute_cognitoidp_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CognitoIdentityProvider Permissions ###")
    tests = [('ListUserPools', 'list_user_pools', (), {'MaxResults':1}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cognito-idp', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/cognito-sync.html
def brute_cognitosync_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating CognitoSync Permissions ###")
    tests = [('ListIdentityPoolUsage', 'list_identity_pool_usage', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cognito-sync', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/config.html
def brute_configservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating ConfigService Permissions ###")
    tests = [('DescribeComplianceByConfigRule', 'describe_compliance_by_config_rule', (), {}, ),
             ('DescribeComplianceByResource', 'describe_compliance_by_resource', (), {}, ), 
             ('DescribeConfigRuleEvaluationStatus', 'describe_config_rule_evaluation_status', (), {}, ),
             ('DescribeConfigurationRecorders', 'describe_configuration_recorders', (), {}, ),  
             ('DescribeConfigRules', 'describe_config_rules', (), {}, ), 
             ('DescribeConfigurationRecorderStatus', 'describe_configuration_recorder_status', (), {}, ), 
             ('DescribeDeliveryChannelStatus', 'describe_delivery_channel_status', (), {}, ),
             ('DescribeDeliveryChannels', 'describe_delivery_channels', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'config', tests)

#Doesnt seem to be working
#http://boto3.readthedocs.io/en/latest/reference/services/cur.html
#def brute_costandusagereportservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
#    print ("### Enumerating CostandUsageReportService Permissions ###")
#    tests = [('DescribeReportDefinitions', 'describe_report_definitions', (), {}, ), 
#            ]
#    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'cur', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/datapipeline.html
def brute_datapipeline_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DataPipeline Permissions ###")
    tests = [('ListPipelines', 'list_pipelines', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'datapipeline', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/devicefarm.html
def brute_devicefarm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DeviceFarm Permissions ###")
    tests = [('ListProjects', 'list_projects', (), {}, ), 
             ('ListDevices', 'list_devices', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'devicefarm', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/directconnect.html
def brute_directconnect_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DirectConnect Permissions ###")
    tests = [('DescribeConnections', 'describe_connections', (), {}, ), 
             ('DescribeLags', 'describe_lags', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'directconnect', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/discovery.html
def brute_discovery_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating ApplicationDiscoveryService Permissions ###")
    tests = [('DescribeAgents', 'describe_agents', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'discovery', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/dms.html
def brute_dms_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DatabaseMigrationService Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}, ), 
             ('DescribeEvents', 'describe_events', (), {}, ), 
             ('DescribeConnections', 'describe_connections', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'dms', tests)

#TODO
def brute_directoryservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DirectoryService Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}, ), 
             ('DescribeEvents', 'describe_events', (), {}, ), 
             ('DescribeConnections', 'describe_connections', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'ds', tests)

#TODO
def brute_dynamodb_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DynamoDB Permissions ###")
    tests = [('DescribeAccountAttributes', 'describe_account_attributes', (), {}, ), 
             ('DescribeEvents', 'describe_events', (), {}, ), 
             ('DescribeConnections', 'describe_connections', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'dynamodb', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/dynamodbstreams.html
def brute_dynamodbstreams_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating DynamoDBStreamsPermissions ###")
    tests = [('ListStreams', 'list_streams', (), {}, ), 
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'dynamodbstreams', tests)



#http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#client
def brute_ec2_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating EC2 Permissions ###")
    tests = [('DescribeInstances', 'describe_instances', (), {'DryRun':True}, ),
             ('DescribeInstanceStatus', 'describe_instance_status', (), {'DryRun':True}, ),
             ('DescribeImages', 'describe_images', (), {'DryRun':True, 'Owners': ['self',]} ),
             ('CreateImage', 'create_image', (), {'InstanceId':'i-0ffffeeeeaa11e111','Name':'testimage','DryRun':True}, ),
             ('DescribeVolumes', 'describe_volumes', (), {'DryRun':True}, ),
             ('CreateVolume', 'create_volume', (), {'AvailabilityZone':'us-east1','Size':8,'DryRun':True}, ),
             ('DescribeSnapshots', 'describe_snapshots', (), {'DryRun':True, 'OwnerIds': ['self',]} ),
             ('CreateSnapshot', 'create_snapshot', (), {'VolumeId':'vol-05777eab71bc97dcb', 'DryRun':True}, ),
             ('DescribeAccountAttributes', 'describe_account_attributes', (), {'DryRun':True}, ),
             ('DescribeAccounts', 'describe_addresses', (), {'DryRun':True}, ),
             ('DescribeAddresses','describe_addresses', (), {'DryRun':True}, ),
             ('DescribeAvailabilityZones', 'describe_availability_zones', (), {'DryRun':True}, ),
             ('DescribeBundleTasks', 'describe_bundle_tasks', (), {'DryRun':True}, ),
             ('DescribeClassicLinkInstances','describe_classic_link_instances', (), {'DryRun':True}, ),
             ('DescribeConversionTasks', 'describe_conversion_tasks', (), {'DryRun':True}, ),
             ('DescribeCustomerGateways', 'describe_customer_gateways', (), {'DryRun':True}, ),
             ('DescribeDhcpOptions', 'describe_dhcp_options', (), {'DryRun':True}, ),
             ('DescribeEgressOnlyInternetGateways','describe_egress_only_internet_gateways', (), {'DryRun':True}, ),

             #The above is more than enough to decide that all/almost all EC2 permissions are there but
             #I'm putting all of them so they can be used for infomration gathering later and i can keep the 
             #ec2 tests blocks consistent across modules

             ('DescribeExportTasks', 'describe_export_tasks', (), {}, ),
             ('DescribeFlowLogs', 'describe_flow_logs', (), {}, ),
             ('DescribeHostReservations', 'describe_host_reservations', (), {}, ),
             ('DescribeHosts', 'describe_hosts', (), {}, ),
             ('DescribeIamInstanceProfileAssociations', 'describe_iam_instance_profile_associations', (), {}, ),
             ('DescribeImportImageTasks', 'describe_import_image_tasks', (), {'DryRun':True}, ),
             ('DescribeImportSnapshotTasks', 'describe_import_snapshot_tasks', (), {'DryRun':True}, ),
             ('DescribeInternetGateways', 'describe_internet_gateways', (), {'DryRun':True}, ),
             ('DescribeKeyPairs', 'describe_key_pairs', (), {'DryRun':True}, ),
             ('CreateKeyPair', 'create_key_pair', (), {'KeyName':'asdfg12345','DryRun':True}, ),
             ('DescribeMovingAddresses', 'describe_moving_addresses', (), {'DryRun':True}, ),
             ('DescribeNatGateways', 'describe_nat_gateways', (), {}, ),
             ('DescribeNetworkAcls', 'describe_network_acls', (), {'DryRun':True}, ),
             ('DescribeNetworkInterfaces', 'describe_network_interfaces', (), {'DryRun':True}, ),
             ('DescribePlacementGroups', 'describe_placement_groups', (), {'DryRun':True}, ),
             ('DescribePrefixLists', 'describe_prefix_lists', (), {'DryRun':True}, ),
             ('DescribeReservedInstances', 'describe_reserved_instances', (), {'DryRun':True}, ),
             ('DescribeReservedInstancesListings', 'describe_reserved_instances_listings', (), {}, ),
             ('DescribeReservedInstancesModifications', 'describe_reserved_instances_modifications', (), {}, ),
             ('DescribeRouteTables', 'describe_route_tables', (), {'DryRun':True}, ),
             ('DescribeScheduledInstances', 'describe_scheduled_instances', (), {'DryRun':True}, ),
             ('DescribeSecurityGroups', 'describe_security_groups', (), {'DryRun':True}, ),
             ('DescribeSpotDatafeedSubscription', 'describe_spot_datafeed_subscription', (), {'DryRun':True}, ),
             ('DescribeSubnets', 'describe_subnets', (), {'DryRun':True}, ),
             ('DescribeTags', 'describe_tags', (), {'DryRun':True}, ),
             ('DescribeVolumeStatus', 'describe_volume_status', (), {'DryRun':True}, ),
             ('DescribeVpcClassicLink', 'describe_vpc_classic_link', (), {'DryRun':True}, ),
             ('DescribeVpcClassicLinkDnsSupport', 'describe_vpc_classic_link_dns_support', (), {}, ),
             ('DescribeVpcEndpointServices', 'describe_vpc_endpoint_services', (), {'DryRun':True}, ),
             ('DescribeVpcEndpoints', 'describe_vpc_endpoints', (), {'DryRun':True}, ),
             ('DescribeVpcPeeringConnections', 'describe_vpc_peering_connections', (), {'DryRun':True}, ),
             ('DescribeVpcs', 'describe_vpcs', (), {'DryRun':True}, ),
             ('CreateVpc', 'create_vpc', (), {'CidrBlock':'10.0.0.0/16','DryRun':True}, ),
             ('DescribeVpnConnections', 'describe_vpn_connections', (), {'DryRun':True}, ),
             ('DescribeVpnGateways', 'describe_vpn_gateways', (), {'DryRun':True}, ),
             ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'ec2', tests)

#http://boto3.readthedocs.io/en/latest/reference/services/elasticbeanstalk.html
def brute_elasticbeanstalk_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating ElasticBeanstalk Permissions ###")
    tests = [('DescribeApplications', 'describe_applications', (), {}, ),
             ('DescribeApplicationVersions', 'describe_application_versions', (), {}),
             ('DescribeConfigurationOptions', 'describe_configuration_options', (), {}),
             ('DescribeEnvironments', 'describe_environments', (), {}),
             ('DescribeEnvironmentHealth', 'describe_environment_health', (), {}, ),
             ('DescribeEnvironmentManagedActionHistory', 'describe_environment_managed_action_history', (), {}),
             ('DescribeEnvironmentManagedActions', 'describe_environment_managed_actions', (), {}),
             ('DescribeEvents', 'describe_events', (), {}),
             ('DescribeInstancesHealth', 'describe_instances_health', (), {}),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'elasticbeanstalk', tests)



#http://boto3.readthedocs.io/en/latest/reference/services/lambda.html
def brute_lambda_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print ("### Enumerating Lambda Permissions ###")
    tests = [('ListFunctions', 'list_functions', (), {}, ),
             ('ListEventSourceMappings', 'list_event_source_mappings', (), {}, ),
            ]
    return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'lambda', tests)


    #('', '', (), {'DryRun':True}, ),





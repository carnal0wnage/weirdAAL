'''
This module handles the core recon functionality by asking all the services
that have functions that done have arguments if we can access them :-)
'''

from libs.brute import *
from libs.s3 import *

# for recon_defaults
from libs.elasticbeanstalk import *
from libs.opsworks import *
from libs.route53 import *
from libs.sts import *

# maps to available services in boto 1.7.4


def module_recon_all():
    '''
    Main recon all module - attempt to connect to each of the services to see if we have some privs
    python3 weirdAAL.py -m recon_all -t demo
    '''
    get_accountid()
    check_root_account()
    brute_acm_permissions()
    brute_acm_pca_permissions()
    brute_alexaforbusiness_permissions()
    brute_apigateway_permissions()
    #  Application Auto Scaling - no usable functions
    brute_appstream_permissions()
    #  AppSync - no usable functions
    brute_athena_permissions()
    brute_autoscaling_permissions()
    brute_autoscaling_plans_permissions()
    brute_batch_permissions()
    brute_budgets_permissions()
    #  CostExplorer
    brute_cloud9_permissions()
    brute_clouddirectory_permissions()
    brute_cloudformation_permissions()
    brute_cloudfront_permissions()
    brute_cloudhsm_permissions()
    brute_cloudhsmv2_permissions()
    brute_cloudsearch_permissions()
    # brute_cloudsearchdomain_permissions() requires a valid cloudsearch domain
    brute_cloudtrail_permissions()
    brute_cloudwatch_permissions()
    brute_codebuild_permissions()
    brute_codecommit_permissions()
    brute_codedeploy_permissions()
    brute_codepipeline_permissions()
    brute_codestar_permissions()
    brute_cognitoidentity_permissions()
    brute_cognitoidp_permissions()
    brute_cognitosync_permissions()
    brute_comprehend_permissions()
    brute_configservice_permissions()
    # connect no functions
    brute_costandusagereportservice_permissions()
    brute_datapipeline_permissions()
    brute_dax_permissions()
    brute_devicefarm_permissions()
    brute_directconnect_permissions()
    brute_applicationdiscoveryservice_permissions()
    brute_dms_permissions()
    brute_directoryservice_permissions()
    brute_dynamodb_permissions()
    brute_dynamodbstreams_permissions()
    brute_ec2_permissions()
    brute_ecr_permissions()
    brute_ecs_permissions()
    brute_efs_permissions()
    brute_elasticache_permissions()
    brute_elasticbeanstalk_permissions()
    brute_elastictranscoder_permissions()
    brute_elasticloadbalancing_permissions()
    brute_elasticloadbalancingv2_permissions()
    brute_emr_permissions()
    brute_es_permissions()
    brute_cloudwatchevents_permissions()
    brute_firehose_permissions()
    brute_fms_permissions()
    brute_gamelift_permissions()
    brute_glacier_permissions()
    brute_glue_permissions()
    brute_greengrass_permissions()
    brute_guardduty_permissions()
    brute_health_permissions()
    brute_iam_permissions()
    brute_importexport_permissions()
    brute_inspector_permissions()
    brute_iot_permissions()
    #  IoTDataPlane  no functions
    #  IoTJobsDataPlane no functions
    brute_kinesis_permissions()
    #  KinesisVideoArchivedMedia no functions
    #  KinesisVideoMedia no functions
    brute_kinesisanalytics_permissions()
    brute_kinesisvideo_permissions()
    brute_kms_permissions()
    brute_lambda_permissions()
    brute_lexmodels_permissions()
    #  LexRuntimeService #no functions
    brute_lightsail_permissions()
    brute_cloudwatchlogs_permissions()
    brute_machinelearning_permissions()
    #  marketplace-entitlement no functions
    #  marketplacecommerceanalytics no functions
    brute_mediaconvert_permissions()
    brute_medialive_permissions()
    brute_mediapackage_permissions()
    brute_mediastore_permissions()
    brute_mediastore_data_permissions()
    #  MarketplaceMetering no functions
    brute_mgh_permissions()
    brute_mobile_permissions()
    brute_mq_permissions()
    brute_mturk_permissions()
    brute_opsworks_permissions()
    brute_opsworkscm_permissions()
    brute_organizations_permissions()
    #  PinPoint no functions
    brute_polly_permissions()
    brute_pricing_permissions()
    brute_rds_permissions()
    brute_redshift_permissions()
    brute_rekognition_permissions()
    brute_resource_groups_permissions()
    brute_resourcegroupstaggingapi_permissions()
    brute_route53_permissions()
    brute_route53domains_permissions()
    brute_s3_permissions()
    brute_sagemaker_permissions()
    #  SageMakerRuntime no functions
    brute_sdb_permissions()
    brute_secretsmanager_permissions()
    brute_serverlessrepo_permissions()
    brute_servicecatalog_permissions()
    brute_servicediscovery_permissions()
    brute_ses_permissions()
    brute_shield_permissions()
    brute_sms_permissions()
    brute_snowball_permissions()
    brute_sns_permissions()
    brute_sqs_permissions()
    brute_ssm_permissions()
    brute_stepfunctions_permissions()
    brute_storagegateway_permissions()
    brute_sts_permissions()
    brute_support_permissions()
    brute_swf_permissions()
    brute_transcribe_permissions()
    brute_translate_permissions()
    brute_waf_permissions()
    brute_waf_regional_permissions()
    brute_workdocs_permissions()
    brute_workmail_permissions()
    brute_workspaces_permissions()
    #  XRay no functions

#  S3 bucket's while we are here...
    get_s3objects_for_account()


def module_recon_defaults():
    '''
    Recon defaults that every account seems to have minus route53_geolocations (static data)
    python3 weirdAAL.py -m recon_defaults -t demo
    '''
    elasticbeanstalk_describe_applications()
    elasticbeanstalk_describe_application_versions()
    elasticbeanstalk_describe_environments()
    elasticbeanstalk_describe_events()
    opsworks_describe_stacks()
    # list_geolocations() # not work looking at, it's static data
    sts_get_accountid_all()

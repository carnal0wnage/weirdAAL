from __future__ import print_function

from libs.brute import *
from libs.s3 import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_recon_all():
    check_root_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_acm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  AlexaForBusiness
    brute_apigateway_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  Application Auto Scaling
    brute_appstream_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  AppSync no usable functions
    brute_athena_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_autoscaling_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_autoscaling_plans_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_batch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_budgets_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  CostExplorer
    #  brute_cloud9_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) Was working now its not
    brute_clouddirectory_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudformation_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudfront_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudhsm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  cloudhsmv2
    brute_cloudsearch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  CloudSearchDomain
    brute_cloudtrail_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudwatch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_codebuild_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_codecommit_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_codedeploy_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_codepipeline_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_codestar_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cognitoidentity_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cognitoidp_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cognitosync_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  Comprehend
    brute_configservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  brute_costandusagereportservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) #Could not connect to the endpoint URL: "https://cur.us-west-2.amazonaws.com/"
    brute_datapipeline_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  DAX
    brute_devicefarm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_directconnect_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_applicationdiscoveryservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_dms_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_directoryservice_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_dynamodb_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_dynamodbstreams_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_ec2_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_ecr_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_ecs_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_efs_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_elasticache_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_elasticbeanstalk_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_elastictranscoder_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_elasticloadbalancing_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_elasticloadbalancingv2_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_emr_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_es_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudwatchevents_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_firehose_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_gamelift_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_glacier_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  Glue
    brute_greengrass_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  GuardDuty
    brute_health_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_iam_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_importexport_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_inspector_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_iot_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  IoTDataPlane  no functions
    #  IoTJobsDataPlane
    brute_kinesis_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  KinesisVideoArchivedMedia
    #  KinesisVideoMedia
    brute_kinesisanalytics_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  KinesisVideo
    brute_kms_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_lambda_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_lexmodels_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  LexRuntimeService #no functions
    brute_lightsail_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_cloudwatchlogs_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_machinelearning_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  marketplace-entitlement no functions
    #  marketplacecommerceanalytics no functions
    #  MediaConvert
    #  MediaLive
    #  MediaPackage
    #  MediaStore
    #  MediaStore-Data
    #  MarketplaceMetering no functions
    #  MigrationHub
    #  Mobile
    #  MQ
    brute_mturk_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_opsworks_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_opsworkscm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_organizations_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  PinPoint no functions
    brute_polly_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  Pricing
    brute_rds_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_redshift_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_rekognition_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  ResourceGroups
    brute_resourcegroupstaggingapi_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_route53_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_route53domains_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_s3_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  SageMaker
    #  SageMakerRuntime
    brute_sdb_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  ServerlessApplicationRepository
    brute_servicecatalog_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  ServiceDiscovery
    brute_ses_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_shield_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_sms_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_snowball_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_sns_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    brute_sqs_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  SSM
    brute_stepfunctions_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  StorageGateway
    brute_sts_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  Support
    #  SWF
    #  TranscribeService
    #  Translate
    #  WAF
    #  WAFRegional
    #  WorkDocs
    #  WorkMail
    brute_workspaces_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  XRay no functions

#  S3 bucket's while we are here...
    get_s3objects_for_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

from __future__ import print_function

from libs.brute import *
from libs.s3 import *


def module_recon_all():
    get_accountid()
    check_root_account()
    brute_acm_permissions()
    #  AlexaForBusiness
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
    #  brute_cloud9_permissions() Was working now its not
    brute_clouddirectory_permissions()
    brute_cloudformation_permissions()
    brute_cloudfront_permissions()
    brute_cloudhsm_permissions()
    #  cloudhsmv2
    brute_cloudsearch_permissions()
    #  CloudSearchDomain
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
    #  Comprehend
    brute_configservice_permissions()
    #  brute_costandusagereportservice_permissions() #Could not connect to the endpoint URL: "https://cur.us-west-2.amazonaws.com/"
    brute_datapipeline_permissions()
    #  DAX
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
    brute_gamelift_permissions()
    brute_glacier_permissions()
    #  Glue
    brute_greengrass_permissions()
    #  GuardDuty
    brute_health_permissions()
    brute_iam_permissions()
    brute_importexport_permissions()
    brute_inspector_permissions()
    brute_iot_permissions()
    #  IoTDataPlane  no functions
    #  IoTJobsDataPlane
    brute_kinesis_permissions()
    #  KinesisVideoArchivedMedia
    #  KinesisVideoMedia
    brute_kinesisanalytics_permissions()
    #  KinesisVideo
    brute_kms_permissions()
    brute_lambda_permissions()
    brute_lexmodels_permissions()
    #  LexRuntimeService #no functions
    brute_lightsail_permissions()
    brute_cloudwatchlogs_permissions()
    brute_machinelearning_permissions()
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
    brute_mturk_permissions()
    brute_opsworks_permissions()
    brute_opsworkscm_permissions()
    brute_organizations_permissions()
    #  PinPoint no functions
    brute_polly_permissions()
    #  Pricing
    brute_rds_permissions()
    brute_redshift_permissions()
    brute_rekognition_permissions()
    #  ResourceGroups
    brute_resourcegroupstaggingapi_permissions()
    brute_route53_permissions()
    brute_route53domains_permissions()
    brute_s3_permissions()
    #  SageMaker
    #  SageMakerRuntime
    brute_sdb_permissions()
    #  ServerlessApplicationRepository
    brute_servicecatalog_permissions()
    #  ServiceDiscovery
    brute_ses_permissions()
    brute_shield_permissions()
    brute_sms_permissions()
    brute_snowball_permissions()
    brute_sns_permissions()
    brute_sqs_permissions()
    #  SSM
    brute_stepfunctions_permissions()
    #  StorageGateway
    brute_sts_permissions()
    #  Support
    #  SWF
    #  TranscribeService
    #  Translate
    #  WAF
    #  WAFRegional
    #  WorkDocs
    #  WorkMail
    brute_workspaces_permissions()
    #  XRay no functions

#  S3 bucket's while we are here...
#commented out until s3 id/key shit is fixed in all modules/libs
    get_s3objects_for_account()

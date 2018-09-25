'''
This file is used to perform some EMR actions
'''

from libs.aws.cloudfront import *


def module_cloudfront_list_distributions():
    '''
    List CloudFront distributions
    python3 weirdAAL.py -m cloudfront_list_distributions -t demo
    '''
    cloudfront_list_distributions()

'''
route53 functions
'''

from libs.aws.route53 import *


def module_route53_list_geolocations():
    '''
    Route53 list geolocations

    python3 weirdAAL.py -m route53_list_geolocations -t demo
    '''
    list_geolocations()

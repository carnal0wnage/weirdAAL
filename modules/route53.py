'''
route53 functions
'''
from  libs.route53 import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_route53_list_geolocations():
	list_geolocations(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
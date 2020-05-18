'''
This file is used to perform various EC2 operations
'''

from libs.aws.ec2 import *


def module_ec2_describe_instances_basic():
    '''
    Basic info about each EC2 instance
    ex:
    [+] Listing instances for region: us-west-2 [+]
    InstanceID: i-XXXXXXXXXXXXXXX, InstanceType: t2.micro, State: {'Code': 80, 'Name': 'stopped'}, Launchtime: 2016-08-25 22:31:31+00:00
    python3 weirdAAL.py -m ec2_describe_instances_basic -t demo
    '''
    describe_instances_basic()


def module_ec2_describe_instances():
    '''
    All info about each EC2 instance
    python3 weirdAAL.py -m ec2_describe_instances -t demo
    '''
    describe_instances()


def module_ec2_write_instances_to_file():
    '''
    For each region write the instanceIDs to a file by region ex (AWSKEYID-region.txt)
    python3 weirdAAL.py -m ec2_write_instances_to_file -t demo
    '''
    write_instances_to_file()


def module_ec2_get_instance_volume_details():
    '''
    Show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
    python3 weirdAAL.py -m ec2_get_instance_volume_details -t demo
    '''
    get_instance_volume_details()


def module_ec2_get_instance_userdata():
    '''
    Show userData sorted by instanceId
    python3 weirdAAL.py -m ec2_get_instance_userdata -t demo
    '''
    get_instance_userdata()


def module_ec2_get_instance_volume_details2():
    '''
    Show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
    python3 weirdAAL.py -m ec2_get_instance_volume_details2 -t demo
    '''
    get_instance_volume_details2()


def module_ec2_review_encrypted_volumes():
    '''
    This function is used to list EBS volumes and whether or not they are encrypted. This is only for "in-use" (running) volumes.
    python3 weirdAAL.py -m ec2_review_encrypted_volumes -t demo
    '''
    review_encrypted_volumes()


def module_ec2_describe_elastic_addresses():
    '''
    This function is used to describe ec2 network addresses.
    python3 weirdAAL.py -m ec2_describe_addresses -t demo
    '''
    describe_elastic_addresses()


def module_ec2_describe_network_interfaces():
    '''
    This function is used to describe ec2 network interfaces.
    python3 weirdAAL.py -m ec2_describe_network_interfaces -t demo
    '''
    describe_network_interfaces()

def module_ec2_describe_publicips():
    '''
    This function is used to describe ec2 network interfaces.
    python3 weirdAAL.py -m ec2_describe_publicips -t demo
    '''
    describe_publicips()

def module_ec2_describe_route_tables():
    '''
    This function describes route tables for each ec2 instance
    python3 weirdAAL.py -m ec2_describe_route_tables -t demo
    '''
    describe_route_tables()


def module_ec2_stop_instance_dryrun(*text):
    '''
    This function attempt to stop the specified InstanceID and region
    passes dry run command so shouldnt "actually" stop it. nice to prove access
    python3 weirdAAL.py -m ec2_stop_instance_dryrun -a 'i-0321f4EXAMPLE','us-east-1' -t yolo
    '''
    ec2_stop_instance_dryrun(text[0][0], text[0][1])


def module_ec2_get_console_screenshot(*text):
    '''
    This function gets a screenshot for the specified InstanceID and region
    python3 weirdAAL.py -m ec2_get_console_screenshot -a 'i-0321f4EXAMPLE','us-east-1' -t yolo
    '''
    get_console_screenshot(text[0][0], text[0][1])


def module_ec2_get_console_output(*text):
    '''
    This function gets the console output for the specified InstanceID and region
    python3 weirdAAL.py -m ec2_get_console_output -a 'i-0321f4EXAMPLE','us-east-1' -t yolo
    '''
    get_console_output(text[0][0], text[0][1])


def module_ec2_get_console_screenshot_all():
    '''
    This function will attempt to screenshot all EC2 instances (loops through all regions)
    python3 weirdAAL.py -m ec2_get_console_screenshot_all -t demo
    '''
    get_console_screenshot_all()


def module_ec2_get_console_output_all():
    '''
    This function will attempt to get the console output all EC2 instances (loops through all regions)
    python3 weirdAAL.py -m ec2_get_console_output_all -t demo
    '''
    get_console_output_all()


def module_ec2_get_console_screenshot_all_region(*text):
    '''
    This function gets a screenshot for all EC2 instances in the specified region
    python3 weirdAAL.py -m ec2_get_console_screenshot_all_region -a us-west-2 -t yolo
    '''
    get_console_screenshot_all_region(text[0][0])


def module_ec2_get_console_output_all_region(*text):
    '''
    This function gets the console output for all EC2 instances in the specified region
    python3 weirdAAL.py -m ec2_get_console_output_all_region -a us-west-2 -t yolo
    '''
    get_console_output_all_region(text[0][0])


def module_ec2_get_console_screenshot_all_region_list(*text):
    '''
    This function gets a screenshot for all EC2 instances in the specified list & region
    useful if for some reason one instance-id wont screenshot, pass it a list of instance-ids for a region
    -See module_ec2_write_instances_to_file to create the list
    python3 weirdAAL.py -m ec2_get_console_screenshot_all_region_list -a 'ASIAJEXAMPLEKEY-us-west-2.txt','us-west-2' -t yolo
    '''
    get_console_screenshot_all_region_list(text[0][0], text[0][1])


def module_ec2_get_console_output_all_region_list(*text):
    '''
    This function gets the console output for all EC2 instances in the specified list & region
    useful if for some reason one instance-id wont screenshot, pass it a list of instance-ids for a region
    -See module_ec2_write_instances_to_file to create the list
    python3 weirdAAL.py -m ec2_get_console_output_all_region_list -a 'ASIAJEXAMPLEKEY-us-west-2.txt','us-west-2' -t yolo
    '''
    get_console_output_all_region_list(text[0][0], text[0][1])


def module_ec2_list_launchable_ami():
    '''
    This function will attempt to get launchable AMIs for the key owner (loops through all regions)
    For each region list launchable AMIs - equivalent to aws ec2 describe-images --executable-users self
    per documentation this doenst list AMIs you own.
    "The following command lists the AMIs for which you have explicit launch permissions. This list does not include any AMIs that you own."
    run ec2_list_owner_ami also to get a list of YOUR account's AMIs

    python3 weirdAAL.py -m ec2_list_launchable_ami -t demo
    '''
    ec2_list_launchable_ami()


def module_ec2_list_owner_ami():
    '''
    This function will attempt to get all AMIs for the key owner (loops through all regions)
    python3 weirdAAL.py -m ec2_list_owner_ami -t demo
    '''
    ec2_list_owner_ami()


def module_ec2_get_snapshots():
    '''
    This function will attempt to get all snapshots for the key owner (loops through all regions)
    python3 weirdAAL.py -m ec2_get_snapshots -t demo
    '''
    ec2_get_snapshots()


def module_ec2_get_snapshots_by_accountid(*text):
    '''
    This function will attempt to get all PUBLIC snapshots for the provided accountid (loops through all regions)
    Useful if you found an accountid and want to see if they have snapshots publicly exposed. Account doing the 
    searching will need AmazonEC2ReadOnlyAccess privileges 
    python3 weirdAAL.py -m ec2_get_snapshots -a 123456789123 -t demo
    '''
    ec2_get_snapshots_by_accountid(text[0][0])

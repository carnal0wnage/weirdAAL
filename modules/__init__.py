import os
from libs.utils.common import *

# Get the application's path (wherever weirdAAL.py is located will be the dirpath )
dirpath = os.getcwd()
# The actual location of this file on the filesystem is the "foldername"
foldername = os.path.dirname(os.path.realpath(__file__))

all_modules = list_all_files(foldername)

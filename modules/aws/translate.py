'''
Translate module
'''

from libs.aws.translate import *


def module_translate_translate_text(*text):
    '''
    translate text ==> text, source_language, target_language

    python3 weirdAAL.py -m translate_translate_text -a 'secure your shit','en','fr' -t demo
    '''
    translate_text(text[0][0], text[0][1], text[0][2])

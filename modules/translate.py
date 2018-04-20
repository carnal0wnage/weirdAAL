'''
Translate module
'''


from libs.translate import *

def module_translate_translate_text(*text):
	'''
	translate text ==> text, source_language, target_language
	'''
	translate_text(text[0][0], text[0][1], text[0][2])

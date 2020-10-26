#!/usr/bin/python3

import struct
import binascii
import sys
import os
import argparse
import re
import subprocess
from impacket.dpapi import  CredentialFile, DPAPI_BLOB, getFlags, FLAGS, ALGORITHMS, ALGORITHMS_DATA
from impacket.structure import Structure, hexdump
from impacket.uuid import bin_to_string
from binascii import unhexlify, hexlify

#144 bytes each
class CRED_HIST(Structure):
	structure = (
	('Paddinga','<L=0'),
	('Guid',"16s=b"),
	('hashAlgo','<L=0'),
	('version','<L=0'),
	('algHash','<L=0'),
	('rounds','<L=0'),
	('sidLen','<L=0'),
	('algCrypt','<L=0'),
        ('shaHashLen','<L=0'),
        ('ntHashLen','<L=0'),
	('iv','16s=b'),
	('SID','28s=b'),

	#'SID' 			/ RPC_SIDAdapter(RPC_SID),
	# 16 should not be hardcoded
	#('_encrypted', '_-encrypted','self["shaHashLen"]')
        #('encrypted',':'),

        #+ 'self["algCrypt"]')
            #+ ((self.["shaHashlen"] + self.["ntHashlen") %16)'),
	#('revision2','<L=0'),
	#('guid','<L=0'),
	)
	def dump(self):
                print("[CRED]")
                print("version         : %8x (%d)" % (self['version'], self['version']))
                print("GUID            : %s" % bin_to_string(self['Guid']))
                print("algHash          : %8x (%d)" % (self['algHash'], self['algHash']))
                print("rounds          : %8x (%d)" % (self['rounds'], self['rounds']))
                print("sidLen          : %8x (%d)" % (self['sidLen'], self['sidLen']))
                print("algCrypt        : %8x (%d)" % (self['algCrypt'], self['algCrypt']))
                print("shaHashLen      : %8x (%d)" % (self['shaHashLen'], self['shaHashLen']))
                print("ntHashLen       : %8x (%d)" % (self['ntHashLen'], self['ntHashLen']))
                print("iv              : %s" % hexlify(self['iv']))

                print("SID             : %s" % ((self['SID'])))



                print()


	#'encrypted'		/ Bytes(this.shaHashLen + this.algCrypt + ((this.shaHashLen + this.algCrypt) % 16)), 
	#'revision2'		/ Int32ul,
	#'guid'			/ GuidAdapter(GUID),

# 24 bytes size
class CredHist(Structure):
	structure = (
        ('Version', '<L=0'),
        ('Guid', "16s=b''"),
	('Data',':'),
	)
	def dump(self):
		print("[CREDHIST]")
		print("Version       : %8x (%d)" % (self['Version'], self['Version']))
		print("Guid          : %s" % bin_to_string(self['Guid']))
		print()


# arguments
parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", help="set CREDHISTORY file")
parser.add_argument("--password", "-p", help="user password")
parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.set_defaults(nopass=False)
args = parser.parse_args()

file_list=[]
sid = ''

if args.file:
	_file=(args.file)
	print(_file)
else:
        print("no file input")
        _file='Microsoft/Protect/CREDHIST'

	#sys.exit()

#Get Size
tam = (os.path.getsize(_file) / 144)
number_of_creds= (int(tam))

fp = open(_file, 'rb')

for cred in range(number_of_creds):
    data = fp.read(144)

    blo = CRED_HIST(data)
    blo.dump()

data = fp.read(24)
blob = CredHist(data)

blob.dump()



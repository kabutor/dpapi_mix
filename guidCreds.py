#!/usr/bin/python3

import struct
import binascii
import sys
import os
import argparse
import re
import subprocess

# arguments
parser = argparse.ArgumentParser()
parser.add_argument("--cred", "-c", help="set Credentials directory")
parser.add_argument("--file", "-f", help="set Credentials file")
parser.add_argument("--masterkey", "-m", help="set masterkey directory file")
parser.add_argument("--sid", "-s", help="set SID(optional)")
parser.add_argument("--password", "-p", help="user password")

args = parser.parse_args()

file_list=[]
sid = ''
if args.cred:
    for f in (os.listdir(args.cred)):
        file_list.append(os.path.join(args.cred, f))
elif args.file:
    file_list.append(args.file)
if args.masterkey:
    #regex to get sid
    if not args.sid:
        try:
            sid = ( re.search('((S-1).*?)/', args.masterkey )[1]  )
        except:
            print("Need to specify SID")
            sys.exit(2)
    else:
        sid= args.sid

for fichero in file_list:
    try:
        f= open( fichero, 'rb') 
        # dwVersion
        hexdata = f.read(16)
        
        # guidProvider
        hexdata=f.read(16)
        # dwMasterkeyversion
        hexdata = f.read(4)
        #print ("Mky Version : %s" % (struct.unpack('<I', hexdata))[0])

        #Masterkey Guid
        hexdata=f.read(8)
        provider = struct.unpack('>IHH', hexdata)
        first= ("%s-%s-%s" % ( binascii.hexlify(struct.pack('I',provider[0])).decode('utf-8') , binascii.hexlify(struct.pack('H',provider[1])).decode('utf-8') , binascii.hexlify(struct.pack('H',provider[2])).decode('utf-8') ) ) 
        second=f.read(2).hex()
        third=f.read(6).hex()
        master_file_name = first + "-" + second + "-" + third
        print("Master Key  : %s" % master_file_name )

        '''  
            print('Master Key  : %s \x1b[6;30;42m \x1b[0m' % master_file_name )
        '''     
        print ()
        f.close()
        if ( (sid) and (args.masterkey) and (args.password) ):
            sal=subprocess.check_output("dpapi.py masterkey -file " + os.path.join(args.masterkey,master_file_name) + " -sid " + sid + " -password " + args.password, shell=True)
            key = (re.search('(0x.*).?', sal.decode('utf-8')))[1]
            print (key)
            sal=subprocess.check_output("dpapi.py credential -file " + fichero + " -key " + key, shell=True )
            print (sal.decode('utf-8'))
    except Exception as e:
        print(e)
        print ("error")


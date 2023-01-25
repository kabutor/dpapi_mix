#!/usr/bin/env python3

#############################################
#
#
#
# 
##########################################
import os, sys
from dpapick3 import blob, masterkey, registry
import binascii
from optparse import OptionParser


parser = OptionParser()
parser.add_option("--dir", metavar="NAME", dest="dir_user", help="User directory, just need this and try to find the rest.")
parser.add_option("--pwd", metavar="HIVE", dest="password", help = ('User password'))
parser.add_option("--mkdir", metavar="NAME", dest="mkdir", help="Masterkey Directory Location")
parser.add_option("--sid", metavar="NAME", dest="sid_value", help="manually specify SID")
(options, args) = parser.parse_args()

if options.dir_user:
    options.mkdir = os.path.join(options.dir_user, 'AppData', 'Roaming', 'Microsoft','Protect')
if (options.mkdir == None):
    print("Need Masterkey Directory option")
    parser.print_help()
    sys.exit(0)

sid = ''
if options.sid_value == None:
    #    print("Get SID")
    i = os.scandir(os.path.join(options.mkdir))
    for d in i:
        if (d.is_dir() and (d.name[0:3] == 'S-1')):
            sid = str(d.name)
            print("Found SID : %s " % sid)
    if sid == '':
        sys.exit('No SID found')
    else:
        options.sid_value = sid

# Decrypt MKs
mkp = masterkey.MasterKeyPool()
mkp.loadDirectory(os.path.join(options.mkdir, options.sid_value))
print("\n")
for mkl in list(mkp.keys.values()):
    for mk in mkl:
        print("MKGUID: %s" % mk.guid.decode())
if options.password == '':
    print('No password specified with --pwd using blank password')

print("\n")
vuelta = mkp.try_credential(sid,options.password)
for mkl in list(mkp.keys.values()):
    for mk in mkl:
        if mk.decrypted:
            print("######################################################################")
            print("MK GUID: %s" % mk.guid.decode())
            print("SHA1 Decoded Key %s" % binascii.hexlify(mk.masterkey.key).decode())


if (vuelta):
    print("######################################################################")
    print("number of MasterKeys decrypted %i" % vuelta)
else:
    print("No MK decrypted")

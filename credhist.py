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
import hashlib
from Cryptodome.Hash import HMAC, SHA512, SHA1
import hmac
#derivekey used to decrypt - impacket
def deriveKey( passphrase, salt, keylen, count, hashFunction):
        keyMaterial = b""
        i = 1
        while len(keyMaterial) < keylen:
                U = salt + struct.pack("!L", i)
                i += 1
                derived = bytearray(hashFunction(passphrase, U))
                for r in range(count - 1):
                        actual = bytearray(hashFunction(passphrase, derived))
                        derived = (int.from_bytes(derived, sys.byteorder) ^ int.from_bytes(actual, sys.byteorder)).to_bytes(len(actual), sys.byteorder)
                keyMaterial += derived
        return keyMaterial[:keylen]

#Decrypt dpapi - impacket
def dataDecrypt(cipherAlgo, hashAlgo, raw, encKey, iv, rounds):
        """Internal use. Decrypts data stored in DPAPI structures."""
        if hashAlgo == ALGORITHMS.CALG_HMAC.value:
            hashModule = SHA1
        else:
            hashModule = ALGORITHMS_DATA[hashAlgo][1]
        prf = lambda p, s: HMAC.new(p, s, hashModule).digest()
        
        derived = deriveKey(encKey, iv, ALGORITHMS_DATA[cipherAlgo][0] + ALGORITHMS_DATA[cipherAlgo][3], count=rounds, hashFunction=prf)
        key, iv = derived[:ALGORITHMS_DATA[cipherAlgo][0]], derived[ALGORITHMS_DATA[cipherAlgo][0]:]
        key = key[:ALGORITHMS_DATA[cipherAlgo][0]]
        iv = iv[:ALGORITHMS_DATA[cipherAlgo][3]]
        cipher = ALGORITHMS_DATA[cipherAlgo][1].new(key, mode=ALGORITHMS_DATA[cipherAlgo][2], IV=iv)
        cleartxt = cipher.decrypt(raw)
        return cleartxt

#Bit of hacking at uuid1 :P
def bin_to_sid(uuid):
    uuid1, uuid2 = struct.unpack('>LL', uuid[:8])
    uuid3, uuid4, uuid5, uuid6, uuid7 = struct.unpack('<LLLLL', uuid[8:])
    return '%s-%s-%s-%s-%s-%s-%s' % ("S-1", uuid2, uuid3, uuid4, uuid5, uuid6, uuid7)

#144 bytes each
class CRED_HIST(Structure):
        structure = (
        ('Paddinga','<L=0'),
        ('Guid',"16s=b"),
        ('hashAlgo','<L=0'),
        ('version','<L=0'),
        ('HashAlgo','<L=0'),
        ('rounds','<L=0'),
        ('sidLen','<L=0'),
        ('CryptAlgo','<L=0'),
        ('shaHashLen','<L=0'),
        ('ntHashLen','<L=0'),
        ('Salt','16s=b'),
        ('SID','28s=b'),
        ('data','48s=b'), # shaHashLen + ntHashLen + ((shaHashLen + ntHashlen) % 16)
        )
        def __init__(self, data = None, alignment = 0):
                if not hasattr(self, 'alignment'):
                        self.alignment = alignment
                
                self.ntlm = None
                self.pwdhash = None
                self.fields    = {}
                self.rawData   = data
                if data is not None:
                        self.fromString(data)
                else:
                        self.data = None
        def dump(self):
                print("[CRED]")
                print("version         : %8x (%d)" % (self['version'], self['version']))
                print("GUID            : %s" % bin_to_string(self['Guid']))
                print("HashAlgo        : %8x (%s)" % (self['HashAlgo'], ALGORITHMS(self['HashAlgo']).name))
                print("rounds          : %8x (%d)" % (self['rounds'], self['rounds']))
                print("sidLen          : %8x (%d)" % (self['sidLen'], self['sidLen']))
                print("CryptAlgo       : %8x (%s)" % (self['CryptAlgo'], ALGORITHMS(self['CryptAlgo']).name))
                print("shaHashLen      : %8x (%d)" % (self['shaHashLen'], self['shaHashLen']))
                print("ntHashLen       : %8x (%d)" % (self['ntHashLen'], self['ntHashLen']))
                print("Salt            : %s" % hexlify(self['Salt']))
                print("SID             : %s" % (bin_to_sid(self['SID'])))
                print("data             : %s" % hexlify(self['data']))
                print()
        #decrypt with enckey - dpapick 
        def decryptWithKey(self, enckey):
                cleartxt = dataDecrypt(self['CryptAlgo'], self['HashAlgo'], self['data'],enckey, self['Salt'], self['rounds'])
                self.pwdhash = cleartxt[:self['shaHashLen']]
                self.ntlm = cleartxt[self['shaHashLen']:self['shaHashLen'] + self['ntHashLen']]

                self.ntlm = self.ntlm.rstrip(b"\x00")
                if len(self.ntlm) != 16:
                    self.ntlm = None
                    #print ("None")
                else:
                    print ("Decrypted:")

def dec_with_hash(hash_pwd, _sid):
    #Derive passwordhash with SID to get decription Key encKey
    return (hmac.new(hash_pwd, (_sid + "\0").encode("UTF-16LE"), digestmod=lambda: hashlib.new('sha1')).digest())
 

def pass_to_hash(password):
    #convert to hash, call dec_with_hash
    return (hashlib.sha1(password.encode("UTF-16LE")).digest())
    


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
parser.add_argument("--key", "-k", help="sha1 key")
parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.set_defaults(nopass=False)
args = parser.parse_args()


if args.file:
    _file=(args.file)
else:
    print("no CREDHIST file input")
    sys.exit()
if args.password:
    _hash = pass_to_hash(args.password) 
elif args.key:
    _hash = bytes.fromhex(args.key)
elif args.nopass:
    _hash =  bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
else:
    print("need to add password/key")
    sys.exit()

_sid='S-1-5-21-2331447286-1659246195-761725538-1001'

#Get Size
tam = (os.path.getsize(_file) / 144)
number_of_creds= (int(tam))
print("Total Creds in file: %i" % number_of_creds )
fp = open(_file, 'rb')

for cred in range(number_of_creds):
    data = fp.read(144)

    blo = CRED_HIST(data)
    sid = bin_to_sid(blo['SID'])    
    enckey = dec_with_hash(_hash, sid )
    blo.decryptWithKey(enckey)
    
    if (blo.ntlm != None):
        print("sha1-> %s" % hexlify(blo.pwdhash))
        print("ntlm-> %s" % hexlify(blo.ntlm) )

data = fp.read(24)
#CredHist Header
blob = CredHist(data)




#Not Working
from impacket.dpapi import  CredentialFile, DPAPI_BLOB, getFlags, FLAGS, ALGORITHMS, ALGORITHMS_DATA
from impacket.structure import Structure, hexdump
from binascii import unhexlify, hexlify
from impacket.uuid import bin_to_string
from Cryptodome.Hash import HMAC, SHA512, SHA1
from Cryptodome.Util.Padding import unpad
import sys

class DPAPI_CAPI(Structure):
    structure = (
	('Version_bis','<L=0'),
        ('Version', '<L=0'),
	
        ('UniqueNameLen', '<L=0'),
        ('SiPublicKeyLen', '<L=0'),
  	('SiPrivateKeyLen', '<L=0'),
	('ExPublicKeyLen', '<L=0'),
	('ExPrivateKeyLen', '<L=0'),
	('HashLen', '<L=0'),
	('SiExportFlagLen', '<L=0'),
	('ExExportFlagLen', '<L=0'),
	('UniqueName', "40s=b"""),
	('Hash', "20s=b"""),
	('_PublicKey','_-PublicKey','self["SiPublicKeyLen"]'),
	('PublicKey',':'),
	#first pvk
	('pkVersion', '<L=0'),
	('guidProvider', "16s=b"),
	('MasterKeyVersion_', '<L=0'),
	('guidMasterKey', "16s=b"),

	('Flags', '<L=0'),
	('DescriptionLen', '<L=0'),
        
	('_Description', '_-Description', 'self["DescriptionLen"]'),
        ('Description', ':'),
        ('CryptAlgo', '<L=0'),
        ('CryptAlgoLen', '<L=0'),
	('SaltLen', '<L=0'),
        ('_Salt', '_-Salt', 'self["SaltLen"]'),
        ('Salt', ':'),

        ('HMacKeyLen', '<L=0'),
        ('_HMacKey', '_-HMacKey', 'self["HMacKeyLen"]'),
        ('HMacKey', ':'),
	
	('HashAlgo', '<L=0'),
        ('HashAlgoLen', '<L=0'),
	('HMacLen', '<L=0'),
        ('_HMac', '_-HMac', 'self["HMacLen"]'),
        ('HMac', ':'),
	
	
        ('DataLen', '<L=0'),
        ('_Data', '_-Data', 'self["DataLen"]'),
        ('Data', ':'),

        ('SignLen', '<L=0'),
        ('_Sign','_-Sign','self["SignLen"]'),
        ('Sign',':'),
        #exTra
	('expkVersion', '<L=0'),                                                                 
        ('exguidProvider', "16s=b"),                                                             
        ('exMasterKeyVersion_', '<L=0'),
        ('exguidMasterKey', "16s=b"),                                                                                                                                                           
                                                                                               
        ('exFlags', '<L=0'),
        ('exDescriptionLen', '<L=0'),                                                            
                                                                                                                                                                                              
        ('_exDescription', '_-exDescription', 'self["exDescriptionLen"]'),
        ('exDescription', ':'),                                                                  
        ('exCryptAlgo', '<L=0'),                                                                                                                                                                
        ('exCryptAlgoLen', '<L=0'),                                                              
        ('exSaltLen', '<L=0'),                                                                   
        ('_exSalt', '_-exSalt', 'self["exSaltLen"]'), 
        ('exSalt', ':'),                                                                         
                                                                                               
        ('exHMacKeyLen', '<L=0'),                                                                
        ('_exHMacKey', '_-exHMacKey', 'self["exHMacKeyLen"]'),                          
        ('exHMacKey', ':'),                                                                                                                                                                     
                                                                                               
        ('exHashAlgo', '<L=0'),                                                                  
        ('exHashAlgoLen', '<L=0'),                                                               
        ('exHMac2KeyLen', '<L=0'),                                                               
        ('_exHMac2Key', '_-exHMac2Key', 'self["exHMac2KeyLen"]'),     
        ('exHMac2Key', ':'),


        ('exDataLen', '<L=0'),                                                                                                                                                                  
        ('_exData', '_-exData', 'self["exDataLen"]'), 
        ('exData', ':'),

        ('exSignLen', '<L=0'),
        ('_exSign','_-exSign','self["exSignLen"]'),
        ('exSign',':'),        
	#('rest', "252s=b"),
    )
    def dump(self):
        print("[CAPI]")
        print("Version          : %8x (%d)" % (self['Version'], self['Version']))
        print("UniqueNameLen    : %8x (%d)" % (self['UniqueNameLen'], self['UniqueNameLen']))
        print("SiPublicKeyLen   : %8x (%d)" % (self['SiPublicKeyLen'], self['SiPublicKeyLen']))
        print("SiPrivateKeyLen  : %8x (%d)" % (self['SiPrivateKeyLen'], self['SiPrivateKeyLen']))

        print("Unique Name      : (%s)" % self['UniqueName'].decode('utf-8'))
        print("Hash             : (%s)" % ((self['Hash'])))
        print("PublicKey        : (%s)" % (hexlify(self['PublicKey'])))
        print()

        print("pkVersion       : (%s)" % (self['pkVersion']))
        print("guidProvider     : (%s)" % (bin_to_string(self['guidProvider'])))

        print("MasterKeyVersion : %8x (%d)" % (self['MasterKeyVersion_'], self['MasterKeyVersion_']))
        print("guidMasterKey    : (%s)" % (bin_to_string(self['guidMasterKey'])))

        print("Flags            : %8x (%s)" % (self['Flags'], getFlags(FLAGS, self['Flags'])))
        print("DescriptionLen   : %8x (%d)" % (self['DescriptionLen'], self['DescriptionLen']))

        print("Description      : %s" % (self['Description'].decode('utf-16le')))
        print("CryptAlgo        : %.8x (%d) (%s)" % (self['CryptAlgo'], self['CryptAlgo'], ALGORITHMS(self['CryptAlgo']).name))
        print("CryptAlgoLen     : %8x (%d)" % (self['CryptAlgoLen'], self['CryptAlgoLen']))
        print("SaltLen          : %8x (%d)" % (self['SaltLen'], self['SaltLen']))

        print("Salt             : %s" % (hexlify(self['Salt'])))
        print("HMacKeyLen : %8x (%d)" % (self['HMacKeyLen'], self['HMacKeyLen']))
        print("HMacKey          : %s" % (hexlify(self['HMacKey'])))
        #print("HashAlgoLen          : %s " % bytes(hexlify(self['HashAlgoLen'])))
        print("HashAlgo         : %.8x (%d) (%s)" % (self['HashAlgo'], self['HashAlgo'], ALGORITHMS(self['HashAlgo']).name))
        print("HMac             : %s" % (hexlify(self['HMac'])))
        print("DataLen          : %8x (%d)" % (self['DataLen'], self['DataLen']))
        print("Data             : %s" % (hexlify(self['Data'])))
        print("SignLen          : %8x (%d)" % (self['SignLen'], self['SignLen']))
        print("Sign             : %s" % (hexlify(self['Sign'])))
        print()


        print("expkVersion       : (%s)" % (self['expkVersion']))
        print("exguidProvider     : (%s)" % (bin_to_string(self['exguidProvider'])))

        print("exMasterKeyVersion : %8x (%d)" % (self['exMasterKeyVersion_'], self['exMasterKeyVersion_']))
        print("exguidMasterKey    : (%s)" % (bin_to_string(self['exguidMasterKey'])))

        print("exFlags            : %8x (%s)" % (self['exFlags'], getFlags(FLAGS, self['exFlags'])))
        print("exDescriptionLen   : %8x (%d)" % (self['exDescriptionLen'], self['exDescriptionLen']))

        print("exDescription      : %s" % (self['exDescription'].decode('utf-16le')))
        print("exCryptAlgo        : %.8x (%d) (%s)" % (self['exCryptAlgo'], self['exCryptAlgo'], ALGORITHMS(self['exCryptAlgo']).name))
        print("exCryptAlgoLen     : %8x (%d)" % (self['exCryptAlgoLen'], self['exCryptAlgoLen']))
        print("exSaltLen          : %8x (%d)" % (self['exSaltLen'], self['exSaltLen']))

        print("exSalt             : %s" % (hexlify(self['exSalt'])))
        print("exHMacKeyLen : %8x (%d)" % (self['exHMacKeyLen'], self['exHMacKeyLen']))
        print("exHMacKey          : %s" % (hexlify(self['exHMacKey'])))
        #print("exHashAlgoLen          : %s " % bytes(hexlify(self['exHashAlgoLen'])))
        print("exHashAlgo         : %.8x (%d) (%s)" % (self['exHashAlgo'], self['exHashAlgo'], ALGORITHMS(self['exHashAlgo']).name))
        print("exHMac2Key         : %s" % (hexlify(self['exHMac2Key'])))
        print("exDataLen          : %8x (%d)" % (self['exDataLen'], self['exDataLen']))
        print("exData             : %s" % (hexlify(self['exData'])))
        print("exSignLen          : %8x (%d)" % (self['exSignLen'], self['exSignLen']))
        print("exSign             : %s" % (hexlify(self['exSign'])))
        print()


    def deriveKey(self, sessionKey):
        def fixparity(deskey):
            from six import indexbytes, b
            temp = b''
            for i in range(len(deskey)):
                t = (bin(indexbytes(deskey,i))[2:]).rjust(8,'0')
                if t[:7].count('1') %2 == 0:
                    temp+= b(chr(int(t[:7]+'1',2)))
                else:
                    temp+= b(chr(int(t[:7]+'0',2)))
            return temp

        if len(sessionKey) > ALGORITHMS_DATA[self['HashAlgo']][4]:
            derivedKey = HMAC.new(sessionKey,  digestmod = ALGORITHMS_DATA[self['HashAlgo']][1]).digest()
        else:
            derivedKey = sessionKey


        if len(derivedKey) < ALGORITHMS_DATA[self['CryptAlgo']][0]:
            # Extend the key
            derivedKey += b'\x00'*ALGORITHMS_DATA[self['HashAlgo']][4]
            ipad = bytearray([ i ^ 0x36 for i in bytearray(derivedKey)][:ALGORITHMS_DATA[self['HashAlgo']][4]])
            opad = bytearray([ i ^ 0x5c for i in bytearray(derivedKey)][:ALGORITHMS_DATA[self['HashAlgo']][4]])
            derivedKey = ALGORITHMS_DATA[self['HashAlgo']][1].new(ipad).digest() + \
                ALGORITHMS_DATA[self['HashAlgo']][1].new(opad).digest()
            derivedKey = fixparity(derivedKey)

        return derivedKey

    def decrypt(self, key, entropy = None):
        keyHash = SHA1.new(key).digest()
        sessionKey = HMAC.new(keyHash, self['Salt'], ALGORITHMS_DATA[self['HashAlgo']][1])
        if entropy is not None:
            sessionKey.update(entropy)

        sessionKey = sessionKey.digest()

        # Derive the key
        derivedKey = self.deriveKey(sessionKey)

        cipher = ALGORITHMS_DATA[self['CryptAlgo']][1].new(derivedKey[:ALGORITHMS_DATA[self['CryptAlgo']][0]],
                                mode=ALGORITHMS_DATA[self['CryptAlgo']][2], iv=b'\x00'*ALGORITHMS_DATA[self['CryptAlgo']][3])
        cleartext = unpad(cipher.decrypt(self['Data']), ALGORITHMS_DATA[self['CryptAlgo']][1].block_size)

        # Now check the signature

        # ToDo Fix this, it's just ugly, more testing so we can remove one
        toSign = (self.rawData[20:][:len(self.rawData)-20-len(self['Sign'])-4])

        # Calculate the different HMACKeys
        keyHash2 = keyHash + b"\x00"*ALGORITHMS_DATA[self['HashAlgo']][1].block_size
        ipad = bytearray([i ^ 0x36 for i in bytearray(keyHash2)][:ALGORITHMS_DATA[self['HashAlgo']][1].block_size])
        opad = bytearray([i ^ 0x5c for i in bytearray(keyHash2)][:ALGORITHMS_DATA[self['HashAlgo']][1].block_size])
        a = ALGORITHMS_DATA[self['HashAlgo']][1].new(ipad)
        a.update(self['HMac'])

        hmacCalculated1 = ALGORITHMS_DATA[self['HashAlgo']][1].new(opad)
        hmacCalculated1.update(a.digest())

        if entropy is not None:
            hmacCalculated1.update(entropy)

        hmacCalculated1.update(toSign)

        hmacCalculated3 = HMAC.new(keyHash, self['HMac'], ALGORITHMS_DATA[self['HashAlgo']][1])
        if entropy is not None:
            hmacCalculated3.update(entropy)

        hmacCalculated3.update(toSign)

        if hmacCalculated1.digest() == self['Sign'] or hmacCalculated3.digest() == self['Sign']:
            return cleartext
        else:
            return None

_file = 'RSA/S-1-5-21-788893716-389553871-1612069284-1001/1bbe947cf904095bea539fab3a6a5326_b04d17e7-4026-436e-8280-19436d49f2b3'
#_file = sys.argv[1]


fp = open(_file, 'rb')
data = fp.read()
#cred = CredentialFile(data)
#print(cred['Size'])
blob = DPAPI_CAPI(data)

#blob.dump()
key=unhexlify("1e4e9a92c72ef519ccc7b4848a2b5181033aa94f335497debfc74994c8f86cf6b15e29a77cabd9fce002a61bea3fbc7e7f23ca26b4ba29051ec29d2b0887811b")
pvk = blob.decrypt(key)
if (pvk):
	fp= open("test.pvk","w+")
	fp.write(pvk)
	fp.close()
	print("ok")
else:
	blob.dump()

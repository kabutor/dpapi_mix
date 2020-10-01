#!/usr/bin/python3

''' Get masterkey GUID from the all the files in %appdata%\Microsoft\Crypto\RSA\<SID>\ 
(you have to pass that location as first argument), if you pass as second argument the
masterkey location folder (%appdata%\Microsoft\Protect\<SID>\ it will check if the file exist '''


import struct
import binascii
import sys
import os
dir_master =''
if (len(sys.argv) < 2):
    print ("dpapi_get_masterkey <PVK encrypted dpapi directory> <masterkey directory>")
    sys.exit(2)
else:
    directory = sys.argv[1]
 
if(len(sys.argv) > 2):
    dir_master = sys.argv[2]
    if (dir_master[:-1] != '/'):
        dir_master=dir_master + '/'
   

for fichero in os.listdir(directory):
    try:
        f= open(directory + fichero, 'rb') 
        # first 4 nothing ?
        hexdata = f.read(36)
        val = struct.unpack('<IIIIIIIII', hexdata)
        #print ("Version %i UniqueNameLen %i SiPublicKeylen %i SiPrivateKeyLen %i ExPublicKeyLen %i ExPrivateKeyLen %i \n HasLen %i SiExportFlagLen %i ExExportFlagLen %i" % val )

        # Unique Name (ASCII)
        hexdata = f.read(44).hex()
        print ("pUniqueName : %s" % bytes.fromhex(hexdata).decode('utf-8'))
        
        #empty value
        hexdata=f.read(20)
      
        hexdata = f.read( val[3] )
        #print ("pSiPublicKey : %s" % hexdata.hex())
        
        hexdata=f.read(4) #version

        hexdata=f.read(8)

        # unpack MasterKey GUID
        provider = struct.unpack('>IHH', hexdata)
        first= ("%s-%s-%s" % ( binascii.hexlify(struct.pack('I',provider[0])).decode('utf-8') , binascii.hexlify(struct.pack('H',provider[1])).decode('utf-8') , binascii.hexlify(struct.pack('H',provider[2])).decode('utf-8') ) ) 
        second=f.read(2).hex()
        third=f.read(6).hex()
        
        hexdata=f.read(4) #version

        hexdata=f.read(8)
        provider = struct.unpack('>IHH', hexdata)
        first= ("%s-%s-%s" % ( binascii.hexlify(struct.pack('I',provider[0])).decode('utf-8') , binascii.hexlify(struct.pack('H',provider[1])).decode('utf-8'), binascii.hexlify(struct.pack('H',provider[2])).decode('utf-8') ) ) 
        second=f.read(2).hex()
        third=f.read(6).hex()
        master_file_name = first + "-" + second + "-" + third
        #If passed masterkey directory check if it exist
        if ( (dir_master != '') and (os.path.isfile(dir_master + master_file_name) ) ):
            print('Master Key  : %s \x1b[6;30;42m \x1b[0m' % master_file_name )
        else:
            print("Master Key  : %s" % master_file_name )
        
        print ()
        f.close()

    except Exception as e:
        print(e)
        print ("error")


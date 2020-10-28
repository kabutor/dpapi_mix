# dpapi_mix

Some things I'm doing using DPAPI/Mimikatz/IMPACKET not working most of this.


# Scripts

guidCreds.py - Bulk extract dpapi encrypted Credentials, you need to supply the user password 
and the masterfile location (%Appdata%\Microsoft\Protect usually). It will dump in 
cleartext the credentials saved.

Will only work if the password used to encrypt in the moment that you saved them is the same as the one you are passing to the program, DPAPI 
encrypt the data with the password at the moment it saved the credentials, it can be different to the actual, old passwords are encrypted
on the CREDHIST file

Use it with -h to see all the options, you can use a single file or a folder
with all the Credentials (usually Appdata\<Local/Roaming>\Microsoft\Credentials) 

Requisites: impacket (dpapi.py from the examples must be in the path)


credhist.py - Dump the contents of the CREDHIST file, I like to know how to decrypt it, but I don't.


dpapicapi.py - My attemp to port dpapi::capi from mimikatz to linux to dump encrypted PVK files on linux. Not working



guidmasterkey.py - Shows and check you have the masterkey needed to decrypt DPAPI PVK files. Not very useful, it was a precursor of guidCreds.py



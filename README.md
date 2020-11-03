# dpapi_mix

Some things I'm doing using DPAPI/Mimikatz/IMPACKET not working some of these...


# Scripts

__guidCreds.py__ - Bulk extract dpapi encrypted Credentials, you need to supply the user password 
and the masterfile location (%Appdata%\Microsoft\Protect usually). It will dump in 
cleartext the credentials saved.

Will only work if the password used to encrypt in the moment that you saved them is the same as the one you are passing to the program, DPAPI 
encrypt the data with the password at the moment it saved the credentials, it can be different to the actual, old passwords are encrypted
on the CREDHIST file

Use it with -h to see all the options, you can use a single file or a folder
with all the Credentials (usually Appdata\<Local/Roaming>\Microsoft\Credentials) 

Requisites: impacket (dpapi.py from the examples must be in the path)


__credhist.py__ - Requires Impacket. Decrypt CREDHIST file, you have to specify the user password or the sha1 key in order to decrypt any of the old user password hashes. You can also use a wordlist to bruteforce it.


__dpapicapi.py__ - My attemp to port dpapi::capi from mimikatz to linux to dump encrypted PVK files on linux. Not working



__guidmasterkey.py__ - Shows and check you have the masterkey needed to decrypt DPAPI PVK files. Not very useful, it was a precursor of guidCreds.py


# License

A lot of code is just copy/paste from other projecst with different licenses so I'm afraid I can't put this code under any specific license, Impacket use some kind of Apache License, and Dpapick is under the GPLv3, wich are the main places I copied things from, I seriously advise against using this code on this legal state on any project. (sorry) 
If you can remove all the impacket code from here, I say the rest, my code included, is under GPLv3.


Impacket https://github.com/SecureAuthCorp/impacket/
Dpapick mis-team https://github.com/mis-team/dpapick

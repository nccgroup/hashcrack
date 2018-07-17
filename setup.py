#
#Released as open source by NCC Group Plc - http://www.nccgroup.com/
#
#Developed by Jamie Riden, jamie.riden@nccgroup.com
#
#http://www.github.com/nccgroup/hashcrack
#
#This software is licensed under AGPL v3 - see LICENSE.txt
#

import os
import urllib.request
import zipfile
import shutil

def is_non_zero_file(fpath):  
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0

def btexec( sexec ):
    print('RUN: '+sexec) 
    os.system(sexec)
    
def main():
    btexec('mkdir dict')
    #check for file existence and download
    print("Installing impacket and other dependencies")
    btexec("pip3 install -r requirements.txt")
    
    print("Checking for dictionary files - will download if not present...")
    if not is_non_zero_file('dict/breachcompilation.txt'):
        if not is_non_zero_file('empdict.zip'):
            urllib.request.urlretrieve ("http://www.blacktraffic.co.uk/pw-dict-public/empdict.zip", "empdict.zip")
        print("Got dictionary zip, expanding...")    
        zip_ref = zipfile.ZipFile('empdict.zip', 'r')
        zip_ref.extractall('.')
        zip_ref.close()

    if not is_non_zero_file('hashcat-4.0.1.7z'):
        print("Got hashcat-4.0.1 (for Windows), expanding...")    
        urllib.request.urlretrieve ("https://hashcat.net/files_legacy/hashcat-4.0.1.7z", "hashcat-4.0.1.7z")
        btexec('7z x hashcat-4.0.1.7z')
            
    if not is_non_zero_file('hashcat-4.1.0.7z'):
        print("Got hashcat-4.1.0 (for UNIX), expanding...")    
        urllib.request.urlretrieve("https://hashcat.net/files/hashcat-4.1.0.7z","hashcat-4.1.0.7z")

    btexec('7z x hashcat-4.1.0.7z')

    print("Getting JksPrivkPrepare.jar - for Java keystores")
    if not is_non_zero_file('JksPrivkPrepare.jar'):
        urllib.request.urlretrieve("https://github.com/floyd-fuh/JKS-private-key-cracker-hashcat/raw/master/JksPrivkPrepare.jar","JksPrivkPrepare.jar")

    print("Getting impacket-0.9.15 - might need to get a different one to match the pip install of impacket")
    if not is_non_zero_file('impacket_0_9_15.zip'):
        urllib.request.urlretrieve("https://github.com/CoreSecurity/impacket/archive/impacket_0_9_15.zip","impacket_0_9_15.zip")
        
    zip_ref = zipfile.ZipFile('impacket_0_9_15.zip', 'r')
    zip_ref.extractall('.')
    zip_ref.close()

    try:
        os.rename('impacket-impacket_0_9_15','impacket')
    except:
        print("Couldn't rename impacket - assuming already exists")

    if not is_non_zero_file('bleeding-jumbo.zip'):
        urllib.request.urlretrieve("https://github.com/magnumripper/JohnTheRipper/archive/bleeding-jumbo.zip","bleeding-jumbo.zip")
        
    zip_ref = zipfile.ZipFile('bleeding-jumbo.zip', 'r')
    zip_ref.extractall('.')
    zip_ref.close()

    try:        
        os.rename('JohnTheRipper-bleeding-jumbo','john')
    except:
        print("Couldn't rename john - assuming already exists")
        
    shutil.copy2('rules/leet2.rule','hashcat-4.0.1/rules/')
    shutil.copy2('rules/leet2.rule','hashcat-4.1.0/rules/')

    shutil.copy2('rules/allcase.rule','hashcat-4.0.1/rules/')
    shutil.copy2('rules/allcase.rule','hashcat-4.1.0/rules/')

    shutil.copy2('rules/nsav2dive.rule','hashcat-4.0.1/rules/')
    shutil.copy2('rules/nsav2dive.rule','hashcat-4.1.0/rules/')

    
        

if __name__== "__main__":
  main()

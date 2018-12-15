#!/usr/bin/python3

#
#Released as open source by NCC Group Plc - http://www.nccgroup.com/
#
#Developed by Jamie Riden, jamie.riden@nccgroup.com
#
#http://www.github.com/nccgroup/hashcrack
#
#This software is licensed under AGPL v3 - see LICENSE.txt
#

import re
import base64
import os
import subprocess
import sys
import shutil
import argparse
import sqlite3
import urllib
import zipfile
import tempfile
import time
import stat
import configparser

def fixpath(path):
   path=re.sub(r'\\\\','\\',path)
   return path

# strip out the given regexp from ifile and stick it in ofile - unique strips out dupes if True
def getregexpfromfile(pattern, ifile, ofile,unique):
    inpfile = open(ifile, 'r', encoding="utf-8")
    outfile = open(ofile, 'w', encoding="utf-8")
    seen={}    
    
    for l in inpfile:
    
        m = re.search(pattern, l)
        if unique:
            try:
                ans=m.group(1)
                
                if re.match(r'\$HEX\[',ans):                    
                    m = re.search(r'\$HEX\[([0-9a-f]+)\]',ans)
                    if m.group(1):
                        ans=m.group(1)
                        ans=bytearray.fromhex(ans).decode('latin_1')
                if not ans in seen:
                    seen[ans]=1
                    outfile.write(ans)
            except:
                print("no match ("+pattern+") line " + l)
        else:
            try:
                ans=m.group(1)
                outfile.write(ans)
            except:
                print("no match ("+pattern+") line " + l)
            
    inpfile.close()
    outfile.close()

def file_age_in_seconds(pathname):
    return time.time() - os.stat(pathname)[stat.ST_MTIME]    

#check if a file exists and is non empty
def is_non_zero_file(fpath):  
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0

def rules_exist(fpath,ruleshome):
    if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
        return True
    if os.path.isfile(ruleshome+fpath) and os.path.getsize(ruleshome+fpath) > 0:
        return True
    return False

def dict_exists(fpath,dicthome):
    if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
        return True
    if os.path.isfile(dicthome+fpath) and os.path.getsize(dicthome+fpath) > 0:
        return True
    return False

    
#halt with message      
def die( message ):
    print(message)
    sys.exit( message )

#map names to types
def friendlymap( name ):
   fmap={'md5':'0',
         'sha1':'100',
         'ntlm':'1000',
         'vbulletin':'2611',
         'ipb':'2811',
         'mysql':'300',
         'lm':'3000',
         'sha256':'1400',
         'sha512':'1700',
         'oracle7':'3100',
         'oracle11':'112',
         'oracle12':'12300',
         'md5crypt':'500',
         'descrypt':'1500',
         'netlmv1':'5500',
         'netlmv2':'5600',
         '7z':'11600',
         'apache':'1600',
         'dcc':'1100',
         'dcc2':'2100',
         'mscache':'1100',
         'mscache2':'2100',
         'mscash':'1100',
         'mscash2':'2100',
         'drupal':'7900',
         'netscaler':'8100',
         'wpa':'2500',
         'phps':'2612',
         'sha3':'5000',
         'sha384':'10800'
   }

   t = fmap.get(name, 'auto')
   return t 

#pick some sensible defaults for the given hashtype
def selectparams( hashtype, nuke, ruleshome, dicthome ):

    # default these, but then see if they're in the config fiile
    
    # dictionaries
    hugedict="Top258Million-probable.txt" 
    bigdict="Top32Million-probable.txt" 
    smalldict="Top95Thousand-probable.txt"
    dumbdict="words.txt"
    crackeddict="cracked-passwords.txt"
        
    # rules
    hugerules="l33tnsa.rule"
    bigrules="l33tpasspro.rule"
    smallrules="l33t64.rule"
    nullrules="null.rule"

    #try:
    if True:
        config = configparser.ConfigParser()
        config.read("winhc.cfg")

        hugedict = config.get('dicts', 'hugedict')
        bigdict = config.get('dicts', 'bigdict')
        smalldict = config.get('dicts', 'smalldict')
        dumbdict = config.get('dicts', 'dumbdict')
        crackeddict = config.get('dicts', 'cracked')

        hugerules = config.get('rules', 'hugerules')
        bigrules = config.get('rules', 'bigrules')
        smallrules = config.get('rules', 'smallrules')
        nullrulres = config.get('rules', 'nullrules')
                        
#    except:
#        print("Error reading config file winhc.cfg, so going with default dicts and rules")

    if not dict_exists(bigdict,dicthome):
        print("Big dict "+bigdict+" doesn't seem to exist - could cause problems. Check config file winhc.cfg")

    if not dict_exists(smalldict,dicthome):
        print("Small dict "+smalldict+" doesn't seem to exist - could cause problems. Check config file winhc.cfg")

    if not rules_exist(hugerules,ruleshome):
        print("Huge rules file "+hugerules+" doesn't seem to exist - could cause problems. Check config file winhc.cfg")

    if not rules_exist(bigrules,ruleshome):
        print("Big rules file "+bigrules+" doesn't seem to exist - could cause problems. Check config file winhc.cfg")

    if not rules_exist(smallrules,ruleshome):
        print("Small rules file "+smallrules+" doesn't seem to exist - could cause problems. Check config file winhc.cfg")        


    dict=''
    rules=''
    inc=0
    
    if nuke:

        #open map.cfg
        with open("map.cfg") as f:
            for line in f:
                try:
                    (key, val) = line.split(':')

                    if key == hashtype:
                        (dict,rules,inc,hr)=val.split(',')
                except:
                    print(line)
                
    else:
        
        #open quickmap.cfg

        with open("quickmap.cfg") as f:
            for line in f:
                try:
                    (key, val) = line.split(':')

                    if key == hashtype:
                        (dict,rules,inc,hr)=val.split(',')
                except:
                    print(line)

    dict=eval(dict)
    rules=eval(rules)
                    
    tp=(dict,rules,int(inc))
        
    return tp

#autodetect the hashtype given the first line of the file
def autodetect( line ):
    
    if re.search(r'(^|:)\$1\$',line):
        print('Autodetected md5crypt')
        return '500'

    if re.search(r'(^|:)\$krb5tgs\$23\$',line):
        print('Autodetected kerberos ticket type 13100')
        return '13100'

    if re.search(r'(^|:)\$krb5pa\$23\$',line):
        print('Autodetected kerberos type 7500')
        return '7500'
    
    if re.search(r'(^|:)\$P\$',line):
        print('Autodetected phpass')
        return '400'

    if re.search(r'(^|:)\$H\$',line):
        print('Autodetected phpass')
        return '400'

    if re.search(r'(^|:)\$8\$',line):
        print('Autodetected Cisco type 8 (pbkdf2-sha256)')
        return '9200'

    if re.search(r'(^|:)\$9\$',line):
        print('Autodetected Cisco type 9 (scrypt)')
        return '9300'

    if re.search(r'(^|:)sha1\$',line):
        print('Autodetected Django SHA1')
        return '124'
    
    if re.search(r'(^|:)\$S\$',line):
        print('Autodetected Drupal')
        return '7900'

    if re.search(r'(^|:)\$PHPS\$',line):
        print('Autodetected PHPS')
        return '2612'

    if re.search(r'(^|:)(A|a)dministrator:500:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:',line):
        print('Autodetected pwdump')
        return 'pwdump'

    if re.search(r'[^:]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:',line):
        print('Autodetected pwdump')
        return 'pwdump'    

    if re.search(r'(^|:)[a-f0-9]{32}:[A-Za-z0-9_]{1,10}$',line):
        print('Autodetect postgres MD5')
        return '12'
    
    if re.search(r'(^|:)\$2(a|b|y)',line):
        print('Autodetected bcrypt')
        return '3200'

    if re.search(r'(^|:)sha512:',line):
        print('Autodetected Cisco sha512 pbkdf2')
        return '12100'
    
    if re.search(r'(^|:)\$5\$',line):
        print('Autodetected sha256crypt')
        return '7400'

    if re.search(r'(^|:)\$6\$',line):
        print('Autodetected sha512crypt')
        return '1800'

    if re.search(r'(^|:)[A-Fa-f0-9]{32}:[A-Fa-f0-9]{13,14}$',line):
        print('Autodetected DCC / ms cache')
        return '1100'

    if re.search(r'(^|:)[A-Fa-f0-9]{32}:[A-Fa-f0-9]{6}$',line):
        print('Autodetected vBulletin (2611)')
        return '2611'

    if re.search(r'(^|:)[A-Fa-f0-9]{32}:.{5}$',line):
        print('Autodetected IPB (2811)')
        return '2811'

    if re.search(r'(^|:)[A-Fa-f0-9{32}:[A-Fa-f0-9]{49}$',line):
        print('Autodetected Citrix netscaler')
        return '8100'

    if re.search(r'(^|:)[A-Fa-f0-9]{126,130}:[A-Fa-f0-9]{40}$',line):
        print('Autodetected IPMI2')
        return '7300'

    if re.search(r'(^|:)[A-Za-z0-9\./]{43}$',line):
        print('Autodetected Cisco type 4')
        return '5700'

    if re.search(r'(^|:)[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{106}$',line):
        print('Autodetected NetLMv2')
        return '5600'

    if re.search(r'(^|:)[A-Fa-f0-9]{32}:[A-Fa-f0-9]{210}$',line):
        print('Autodetected NetLMv2')
        return '5600'

    if re.search(r':[a-fA-f0-9]{48}:[a-fA-f0-9]{48}:',line):
        print('Autodetected NetLMv1')
        return '5500' 

    if re.search(r'(^|:)[A-Za-z0-9\./]{16}$',line):
        print('Autodetected Cisco ASA')
        return '2400'   
    
    if re.search(r'(^|:)[A-Za-z0-9\./]{13}$',line):
        print('Autodetected descrypt')
        return '1500'

    if re.search(r'(^|:)[A-Fa-f0-9]{40}$',line):
        print('Autodetected SHA1')
        return '100'

    if re.search(r'(^|:)[A-Fa-f0-9]{64}$',line):
        print('Autodetected SHA256')
        return '1400'

    if re.search(r'(^|:)[A-Fa-f0-9]{96}$',line):
        print('Autodetected SHA384')
        return '10800'

    if re.search(r'(^|:)[A-Fa-f0-9]{128}$',line):
        print('Autodetected SHA512')
        return '1700'

    if re.search(r'(^|:)[A-Fa-f0-9]{786}',line):
        print('Autodetected WPA/WPA2')
        return '2500'

    if re.search(r'(^|:)\$apr1\$',line):
        print('Autodetected apache MD5\n')
        return '1600' 

    if re.search(r'(^|:)\$DCC2',line):
        print('Autodetected DCC2 / mscache2')
        return '2100'

    if re.search(r'(^|:)\{SHA\}',line):
        print('Autodetected nsldap SHA1')
        return '101'

    if re.search(r'(^|:)\{SSHA256\}',line):
        print('Autodetected ldap SHA256')
        return '1411'

    if re.search(r'(^|:)\{SSHA512\}',line):
        print('Autodetected ldap SHA512')
        return '1711'
    
    if re.search(r'(^|:)\{SSHA\}',line):
        print('Autodetected ldap SSHA1')
        return '111'

    if re.search(r'(^|:)0x0100',line):
        if re.search(r'(^|:)0x[A-Fa-f0-9]{52}$',line):
            print('Autodetected MSSQL2005')
            return '132'
        if re.search(r'(^|:)0x[A-Fa-f0-9]{92}$',line):
            print('Autodetected MSSQL2000')
            return '131'

    if re.search(r'(^|:)0x0200',line):
        print('Autodetected MSSQL2012+')
        return '1731'

    if re.search(r'(^|:)\{smd5\}',line):
        print('Autodetected AIX smd5')
        return '6300'

    if re.search(r'(^|:)\{ssha1\}',line):
        print('Autodetected AIX ssha1')
        return '6700'

    if re.search(r'(^|:)\{ssha256\}',line):
        print('Autodetected AIX ssha256')
        return '6400'

    if re.search(r'(^|:)\{ssha512\}',line):
        print('Autodetected AIX ssha512')
        return '6500'
    
    if re.search(r'(^|:)[A-Fa-f0-9]{40}$',line):
        print('Autodetected MySQL5')
        return '8100'

    if re.search(r'(^|:)[A-fa-f0-9]{60}$',line):
        print('Autodetected Oracle (112) - but it needs a hash between the first 40 and last 20 for some reason')
        return '112'

    if re.search(r'(^|:)[A-fa-f0-9]{40}:[A-fa-f0-9]{20}$',line):
        print('Autodetected Oracle (112)')
        return '112' 

    if re.search(r'(^|:)[A-fa-f0-9]{32}$',line):
        print('Autodetected NTLM. Probably - or, it might be MD5 (100)x')
        ans=input('Ambigious input; could be NTLM, MD5 or MySQL5. Please specify on command line with -t md5 or -t ntlm. For now, enter "ntlm" (default), "md5" : ')
        if (re.search(r'md5',ans, re.IGNORECASE)):
            return '0'
        return '1000'  
       
    return ''

def btexec( sexec, show=0 ):
    if not show:
        print('RUN: '+sexec) 
    os.system(sexec)

#actually do the hashcat runs
#this can get somewhat complex depending on what it's been asked to do

def runhc( hashcathome, pwdfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdictoverride, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, username, nuke, potfile, noinc, show, skip, restore, force, remove):

    hcbin='hashcat64.exe'

    crackeddict='cracked-passwords.txt'
    
    try:
        config = configparser.ConfigParser()
        config.read("winhc.cfg")

        dicthome = config.get('paths', 'dict')
        if not re.search(r'\\$',dicthome):
            dicthome+='\\'
            
        crackeddict = config.get('dicts', 'cracked')

    except:
        print("Error getting cracked dict")
        
    if rulesoverride:
        r=rulesoverride
        if not is_non_zero_file(r):
            r='rules'+pathsep+r
    else:
        r=ruleshome+rules    

    if dictoverride:
        d=dictoverride
        if not is_non_zero_file(d):
            d='dict'+pathsep+d
    else:
        if not re.search('^/',dict):
            d=dicthome+dict
        
    if rightdictoverride:        
        if not is_non_zero_file(rightdictoverride):
            if not re.search('^/',rightdictoverride):
                rightdictoverride='dict'+pathsep+rightdictoverride

    if username:
        username='--username'
    else:
        username=''

    if potfile:
        potfile="--potfile-path "+potfile
    else:
        potfile=''

    trailer=trailer+' '+potfile+' '+username

    if skip:
        skip=' --skip '+skip
    else:
        skip=''

    if restore:
        restore=' --restore'

        if not show:
            run_command(hcbin+' '+ trailer + restore,hashcathome)
            return
    else:
        restore=''

    if remove:
        remove=' --remove '
        trailer=trailer+' '+remove
    else:
        remove=''

    if force:
        force=' --force '
        trailer=trailer+' '+force
    else:
        force=''
        
    if show:
        trailer=' '+potfile+' '+username
        run_command(hcbin+' -m '+hashtype+' '+pwdfile+' --show --quiet '+trailer,hashcathome)
        return

    if not noinc:
        if inc>0:
            if not mask:
                print("Incremental run up to "+str(inc))
                run_command(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' -i --increment-max='+str(inc)+' '+trailer,hashcathome)
        else:
            print("Skipping inc (inc " + str(inc) + ")")        
    else:
        print("Skipping inc (--noinc)")        

    if lmask:
        print("Using specified left mask and dict: "+lmask)        
        run_command(hcbin+' -a7 -m '+hashtype+' '+pwdfile+' '+lmask+' '+d+' -i '+trailer+skip,hashcathome)
    else:    
        if rmask or mask:
            if mask:
                print("Using specified mask "+mask)
                if re.match('\?',mask): 
                    run_command(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' '+mask+' -i '+trailer+skip,hashcathome)
                else:
                    run_command(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' '+mask+' '+trailer+skip,hashcathome)
            if rmask:
                print("Using specified dict + right mask: "+rmask) 
                run_command(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' '+d+' -i '+rmask+' '+trailer+skip,hashcathome)
        else:
            if rightdictoverride:
                #if we've got right dict override, this is a cross product (-a1) 
                print("Using specified left and right dictionaries")
                run_command(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+d+' '+rightdictoverride+'  '+trailer+skip,hashcathome)
            else:
                #otherwise, "normal" dict + rules run
                print("Using dict and rules")        
                run_command(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' '+dicthome+crackeddict+' '+d+' -r '+r+'  --loopback '+trailer+skip,hashcathome)

                if dolast==1:
                    run_command(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+crackeddict+' '+d+' '+dicthome+'/last3.txt '+trailer,hashcathome)

                    
                
#get first line
def getfirstline( file ):

    first_line = ''
    
    try:
        with open(file,encoding='utf-8') as f:
            first_line = f.readline().strip()
    except:
        print("Couldn't parse first line of file")
        
    return first_line

#run a shell command
def run_command(command,scwd):

    print("CWD "+scwd)
    print("Command "+command)

    if scwd is not None:
        p = subprocess.Popen(command, shell=True,
                             cwd=scwd,                             
                             stderr=subprocess.STDOUT)
        junk = p.communicate()


#main - read the options and do the set up for the cracking
def main():

    #needs to be run with python3
    if sys.version_info < (3,0):
        print("*** Needs python3 for utf-8 / encoding support")        
        
    assert sys.version_info >= (3,0)

    print("Windows compiled version running...")

    #declarations

    exe='.bin'  # default to Linux for the moment 
    minlength=1 # min length for -a3 attacks
    status=''
    cachetime=3600
    maskattack=0
    
    # setup my defaults
    hashtype     = 'auto'   # autodetect
    hashcathome  = 'hashcat-4.0.1'
    
    dicthome='dict'
    ruleshome='rules'

    print("Loading config")
#    try:
    if True:
        config = configparser.ConfigParser()
        config.read("winhc.cfg")

        hashcathome = config.get('paths', 'hc')

        if re.search(r'\\$',hashcathome):
            hashcathome=hashcathome[:-1]
        
        ruleshome = config.get('paths', 'rules')
        
        if not re.search(r'\\$',ruleshome):
            ruleshome+='\\'        
            
        dicthome = config.get('paths', 'dict')

        if not re.search(r'\\$',dicthome):
            dicthome+='\\'



        print("Ruleshome "+ruleshome)
        
        print("Dicthome "+dicthome)
        print("HChome "+hashcathome)
 #   except:
 #       print("Error reading config files, so going with default dicts and rules")

    # declarations
    trailer=''
    dict=''
    inc=0
    mininc=1
    dolast=0
    rules='best64.rule'
    colon=''
    pathstyle=''
    pathsep='/'
    fhash=''
    omenfile=''
    prince=''
    princemin='8'
    princemax='28'
    
    # for hashcat4
    #crackopts=" -O --quiet "
    crackopts=" -O "

    uname=''
    loc=''
    cygwin=0

    inc=0
    remove=''
    incr=''
    unix=0
            
    parser = argparse.ArgumentParser(description='Description of your program')
    parser.add_argument('-i','--input', help='Input file' )
    parser.add_argument('--hash', help='Input hash' )
    parser.add_argument('-m','--mask', help='Mask to use')
    parser.add_argument('--rmask', help='Right hand mask to use with dict')
    parser.add_argument('--lmask', help='Left hand mask to use with dict')
    parser.add_argument('-t','--type', help='Hash type')
    parser.add_argument('-d','--dict', help='Dictionary override')
    parser.add_argument('-e','--rightdict', help='Second dictionary override')
    parser.add_argument('-r','--rules', help='Rules override')
    parser.add_argument('--potfile', help='Potfile override')
    parser.add_argument('-a','--mininc', help='Min increment')
    parser.add_argument('-z','--maxinc', help='Max increment')    
    parser.add_argument('--skip', help='Skip argument to hashcat')
    
    parser.add_argument('--restore', action="store_true", help='Restore to last session')
    parser.add_argument('-s','--show', action="store_true", help='Just show stuff')
    parser.add_argument('-l','--last', action="store_true", help='Use last3 file together with the given or default dictionary')
    parser.add_argument('--force', action="store_true", help='Run with CPU as well. Gets you up to 8% percent extra oomph, depending on hash type')
    parser.add_argument('--remove', action="store_true", help='Remove found hashes from input file')
    parser.add_argument('-w','--words', action="store_true", help='Use words file')
    parser.add_argument('--noinc', action="store_true", help='Don not use increment')
    parser.add_argument('-u','--username', action="store_true", help='Override username flag')
    parser.add_argument('-q','--quick', action="store_true", help='Do more')
    parser.add_argument('-f','--full', action="store_true", help='Do more')
    
    args = parser.parse_args()

    if not args.input and not args.hash:
        die("Please specify [--input|-i] <input file> or --hash <input hash>") 
    
    infile=args.input
    show=args.show
    inhash=args.hash
    words=args.words
    mask=args.mask
    username=args.username
    dolast=args.last
    quick=args.quick
    full=args.full
    skip=args.skip
    restore=args.restore
    remove=args.remove
    force=args.force
    stype=args.type
    rightdict=args.rightdict
    mininc=args.mininc
    maxinc=args.maxinc

    noinc=args.noinc

    infile=os.path.abspath(infile)

    #platform identification
    nuke=0
    
    if full is not None:
        nuke=1
        
    if quick is not None:
        noinc=1
        nuke=0

    if not show:
        print("Running under win32")
    exe='.exe'
    pathstyle='win32'
    pathsep=r'\\'

    trailer=crackopts+' --session hc'

    if maxinc is not None:
        maxinc=int(maxinc)

    if mininc is not None:
        mininc=int(mininc)
    else:
        mininc=0

    if rightdict is not None:
        if not is_non_zero_file(rightdict):
            print("Can't find dictionary file "+rightdict)
            sys.exit(1)
        
    dictoverride=args.dict

    if dictoverride is not None:
        dictoverride=os.path.abspath(dictoverride)
        if not is_non_zero_file(dictoverride):
            print("Can't find dictionary file "+dictoverride)
            sys.exit(1)


    rightdictoverride=args.dict

    if rightdictoverride is not None:
        rightdictoverride=os.path.abspath(rightdictoverride)
        if not is_non_zero_file(rightdictoverride):
            print("Can't find right dictionary file "+rightdictoverride)
            sys.exit(1)
       
    rulesoverride=args.rules

    if rulesoverride is not None:

        rulesoverride=os.path.abspath(rulesoverride)
                
        if not is_non_zero_file(rulesoverride):
            print("Can't find rules file "+rulesoverride)
            sys.exit(1)
        
    potfile=args.potfile

    if potfile is not None:
        potfile=os.path.abspath(potfile)
    
    rmask=args.rmask
    lmask=args.lmask

    if infile is not None:
        tmpfile=infile+'.tmp'
        tmpfile2=infile+'.tmp2'
        
    if inhash is not None:
        infile=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.hash.tmp'
        tmpfile=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.tmp'
        tmpfile2=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.tmp2'
        outfile = open(infile,'w')
        outfile.write(inhash)
        outfile.close()
        print(infile)

    #try relative path first
    hcpath = 'hashcat-5.1.0'
    hcpath=os.path.abspath(hcpath)
    
    try:
        config = configparser.ConfigParser()
        config.read("winhc.cfg")
        hcpath = config.get('paths', 'hc')

        if re.search(r'\\$',hashcathome):
            hashcathome=hashcathome[:-1]        
    except:
        print("Couldn't read config file")
    
    hashtype=args.type
    
    if not hashtype:
        hashtype='auto'
    else:
        #remap friendly name to numeric if need be 
        if re.match('^[a-zA-Z][a-zA-z0-9]+$',hashtype):
            hashtype=friendlymap(hashtype)        

            
    if infile:
        if not show:
            print("Reading file: "+infile)
        if re.search(r'\.db$',infile):
            hashtype='responder'
            stype='responder'

        if re.search(r'\.jks$',infile):
            hashtype='jks'
            stype='jks'
                
        if re.search(r'\.7z$',infile):
            hashtype='7z'
            username=1
            stype='7z'
        
        if re.search(r'\.pdf$',infile):
            hashtype='pdf'
            stype='pdf'

        if re.search(r'\.(xls|doc)x?$',infile):
            hashtype='msoffice'
            stype='msoffice'

        if re.search(r'\.zip$',infile):
            hashtype='ifm'
            stype='ifm'

#ifm support
#C:\>ntdsutil
#ntdsutil: activate instance ntds
#ntdsutil: ifm
#ifm: create full c:\temp\ifm
#ifm: quit
#ntdsutil: quit
#Then zip c:\temp\ifm and submit this.
            
    if infile:
        line=getfirstline(infile)
    else:
        line=inhash

    if hashtype=='auto':
        hashtype=autodetect(line)
        if hashtype=='pwdump':
            stype='pwdump'        

    #preprocess oracle? TODO

    # how many colons we're expecting by hash type
    colonmap={ '10':1,
               '11':1,
               '12':1,
               '20':1,
               '21':1,
               '22':1,
               '23':1,
               '30':1,
               '40':1,
               '50':1,
               '60':1,
               '110':1,
               '112':1,
               '120':1,
               '121':1,
               '130':1,
               '140':1,
               '150':1,
               '160':1,
               '1100':1,
               '1410':1,
               '1420':1,
               '1430':1,
               '1440':1,
               '1450':1,
               '1460':1,
               '1710':1,
               '1720':1,
               '1730':1,
               '1740':1,
               '1750':1,
               '1760':1,
               '2410':1,
               '2611':1,
               '2711':1,
               '2811':1,
               '3100':1,
               '3710':1,
               '3800':1,
               '3910':1,
               '4010':1,
               '4110':1,
               '4520':1,
               '4521':1,
               '4522':1,
               '4800':2,
               '4900':1,
               '5300':8,
               '5400':8,
               '5500':5,
               '5600':5,
               '5800':1,
               '6600':2,
               '6800':2,
               '7300':1,
               '8200':3,
               '8300':3,
               '8400':1,
               '8900':5,
               '9720':1,
               '9820':1,
               '10100':3,
               '10420':1,
               '10900':3,
               '11000':1,
               '11500':1,
               '11900':3,
               '12000':3,
               '12100':3,
               '12600':1,
               '13500':1,
               '13800':1,
               '13900':1,
               '14000':1,
               '14100':1,
               '14400':1,
               '14900':1,
               '15000':1 }

    colons=line.count(':')
    expectedcolons=colonmap.get(hashtype,0)

    #if we've got more colons than that, need --username flag
    if colons>expectedcolons:
       username=1
       print(colons)
       print(expectedcolons)
       print(hashtype)
                    
    if not show:
        print("Cracking "+ hashtype + " type hashes")
    
    hcbin=hcpath

    #preprocess some types
    
    #juniper/palo alto/ios type 5
    if hashtype=='juniper' or hashtype=='paloalto' or hashtype=='ios5':
        getregexpfromfile(r'(\$1\$[^ ]+)',infile,tmpfile,False)
        infile=tmpfile
        hashtype='500'
        stype=''          

    # deal with non-numeric (special) types first
    if stype and not re.match(r'^\d+$',hashtype):
        # most are preprocessed to temp file, then normal crack

        #pwdump - do the LM stuff for cribs and then all case permuatations of that. then normal crack
        if stype=='pwdump':
            if not show:
                run_command(hcbin+' -a3 -m 3000 '+infile+' ?a?a?a?a?a?a?a '+trailer,hashcathome)
                run_command(hcbin+' -a3 -m 3000 '+infile+' ?a?a?a?a?a?a?a --show --quiet -o '+tmpfile,hashcathome)
                
                inpfile = open(tmpfile,'r')
                outfile = open(tmpfile2,'w')
                l = inpfile.read()
                
                m = re.search(':([^:]+)$', l)
                ans=m.group(1)
                outfile.write(ans)
                
                inpfile.close()
                outfile.close()

                hashtype='1000'
            
                run_command(hcbin+' -a0 -m '+hashtype+' '+infile+' '+tmpfile2+' -r rules/allcase.rule '+trailer,hashcathome )

            hashtype='1000'

            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc

            runhc(hashcathome, infile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, username, nuke, potfile, noinc, show, skip, restore, force, remove)

        #responder DB, so unpack and then run
        if stype=='responder':
            conn = sqlite3.connect(infile)
            
            outfile = open(tmpfile,'w')

            recs=0
            
            for row in conn.execute("SELECT fullhash FROM responder where type like 'NTLMv2%'"):
                outfile.write(list(row)[0])
                recs=recs+1
                
            outfile.close()

            if recs>0: # if there are any NetLMv2 hashes
                hashtype='5600'

                (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

                if maxinc is not None:
                    inc=maxinc
            
                runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, username, nuke, potfile, noinc, show, skip, restore, force, remove)
            else:
                print("No NetLMv2 hashes obtained - check sqlite3 install")

            recs=0
            
            for row in conn.execute("SELECT fullhash FROM responder where type like 'NTLMv1%'"):
                outfile.write(list(row)[0])
                recs=recs+1
                
            outfile.close()
                    
            if recs>0: # if there are any NetLMv1 hashes
                hashtype='5500'

                (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

                if maxinc is not None:
                    inc=maxinc
                
                runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, username, nuke, potfile, noinc, show, skip, restore, force, remove)
            else:
                print("No NetLMv1 hashes obtained - check sqlite3 install")
            

    else:
        #not one of the special cases
        if hashtype=='':
            die("Couldn't autodetect, please specify manually")
        
        #"normal" crack goes here
        if not show:
            print("Cracking hash type "+hashtype)
        
        (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

        if maxinc is not None:
            inc=maxinc

        if not show:
            print("Selected rules: "+rules+", dict "+dict+", inc "+str(inc))
        
        runhc(hashcathome, infile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, username, nuke, potfile, noinc, show, skip, restore, force, remove)
  
if __name__== "__main__":
  main()


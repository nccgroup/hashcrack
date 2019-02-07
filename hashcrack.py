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
#TODO preprocessors like prince, OMEN
#TODO graph flag
#TOD all files need to be abspathd
#TODO merge hashcrackwin hashcrack

#import platform
# platform.system - Linux / Windows

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
import platform

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
    if os.path.isfile(ruleshome+'/'+fpath) and os.path.getsize(ruleshome+'/'+fpath) > 0:
        return True
    return False

def dict_exists(fpath,dicthome):
    if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
        return True
    if os.path.isfile(dicthome+'/'+fpath) and os.path.getsize(dicthome+'/'+fpath) > 0:
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
    massivedict="Top2Billion-probable.txt" 
    hugedict="breachcompilation.txt" 
    bigdict="Top258Million-probable.txt" 
    smalldict="Top95Thousand-probable.txt"
    dumbdict="words.txt"
        
    # rules
    hugerules="rules/l33tnsa.rule"
    bigrules="rules/l33tpasspro.rule"
    smallrules="rules/l33t64.rule"
    nullrules="rules/null.rule"

    try:
        config = configparser.ConfigParser()
        config.read("hashcrack.cfg")
        massivedict = config.get('dicts', 'massivedict')
        hugedict = config.get('dicts', 'hugedict')
        bigdict = config.get('dicts', 'bigdict')
        smalldict = config.get('dicts', 'smalldict')
        dumbdict = config.get('dicts', 'dumbdict')

        hugerules = config.get('rules', 'hugerules')
        bigrules = config.get('rules', 'bigrules')
        smallrules = config.get('rules', 'smallrules')
        nullrulres = config.get('rules', 'nullrules')
                        
    except:
        print("Error reading config files, so going with default dicts and rules")

    if not dict_exists(massivedict,dicthome):
        print("Massive dict "+massivedict+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")

    if not dict_exists(bigdict,dicthome):
        print("Big dict "+bigdict+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")

    if not dict_exists(smalldict,dicthome):
        print("Small dict "+smalldict+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")

    if not rules_exist(hugerules,ruleshome):
        print("Huge rules file "+hugerules+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")

    if not rules_exist(bigrules,ruleshome):
        print("Big rules file "+bigrules+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")

    if not rules_exist(smallrules,ruleshome):
        print("Small rules file "+smallrules+" doesn't seem to exist - could cause problems. Check config file hashcat.cfg")        

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

    try:
        dict=eval(dict)
        rules=eval(rules)
        inc=eval(inc)
    except:
        #guess
        dict=eval('bigdict')
        rules=eval('smallrules')
        inc=0

    tp=(dict,rules,int(inc))
        
    return tp

def autodetect( line ):

    with open("regmap.cfg") as f:
        for cfgline in f:
            try:
                (regexp, type, hr) = cfgline.split('!')
                
                if re.search(regexp,line):
                    print('Autodetected '+ hr)
                    return type
                
            except:
                print("Couldn't interpret " + cfgline) 

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

#run a shell command
def btexeccwd(command,scwd,show=0):

    if not show:
        print("RUN: "+command)
    
    if scwd is not None:
        p = subprocess.Popen(command, shell=True,
                             cwd=scwd,                             
                             stderr=subprocess.STDOUT)
        junk = p.communicate()

#actually do the hashcat runs
#this can get somewhat complex depending on what it's been asked to do

def runhc( hashcathome, pwdfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdictoverride, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove):

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
        print("Failed to read config file\n")
            
    if rulesoverride:
        r=rulesoverride
        if not is_non_zero_file(r):
            r='rules'+pathsep+r
    else:
        if not re.search('^/',rules):            
            r=ruleshome+pathsep+rules    

    if dictoverride:
        d=dictoverride
        if not is_non_zero_file(d):
            d='dict'+pathsep+d
    else:
        if not re.search('^/',dict):
            d=dicthome+pathsep+dict
        
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
            btexeccwd(hcbin+' '+ trailer + restore,hashcathome)
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

    if nuke:
        found=1
        
    if show:
        trailer=' '+potfile+' '+username
        btexeccwd(hcbin+' -m '+hashtype+' '+pwdfile+' --show --quiet '+trailer, hashcathome)
        return

    if crib:
        print("Processing crib file...")
        tmpcrib=crib+'.tmp'
        btexeccwd(hcbin+' --stdout '+crib+'  -r '+ruleshome+pathsep+'leet2.rule -o '+tmpcrib,hashcathome)
        btexeccwd(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' '+tmpcrib+' -r '+ruleshome+pathsep+'best64.rule --loopback '+trailer,hashcathome)

    if not noinc:
        if inc>0:
            if not mask:
                print("Incremental run up to "+str(inc))
                btexeccwd(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' -i --increment-max='+str(inc)+' '+trailer,hashcathome)
        else:
            print("Skipping inc (inc " + str(inc) + ")")        
    else:
        print("Skipping inc (--noinc)")        

    if found:
        print("Using previous found list with variations")
        #run list of found passwords against the new ones, various combinations
        btexeccwd(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' found.txt ?a?a -i '+trailer,hashcathome)
        btexeccwd(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' found.txt -r '+ruleshome+pathsep+'best64.rule --loopback '+trailer,hashcathome)
        btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' found.txt '+dicthome+'/last3.txt '+trailer,hashcathome)

        if is_non_zero_file('dict/found.txt'):
            btexeccwd(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' dict/found.txt ?a?a -i '+trailer,hashcathome)
            btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' dict/found.txt '+dicthome+'/last3.txt '+trailer,hashcathome)
            if dolast==1:
                btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+'/found.txt '+dicthome+'/last4.txt '+trailer,hashcathome)
        
        if dolast==1 or nuke:
            btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' found.txt '+dicthome+'/last4.txt '+trailer,hashcathome)

    if words:
        print("Using bog standard dictionary words with variations")
        btexeccwd(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' '+dicthome+'/words.txt ?a?a -i '+trailer,hashcathome)
        btexeccwd(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' '+dicthome+'/words.txt -r '+ruleshome+pathsep+'best64.rule --loopback '+trailer,hashcathome)
        btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+'/words.txt '+dicthome+'/last3.txt '+trailer,hashcathome)
                
        if dolast==1 or nuke:
            btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+'/words.txt '+dicthome+'/last4.txt '+trailer,hashcathome)


    if phrases:
        print("Using phrases with variations")
        btexeccwd(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' '+dicthome+'/phrases.txt ?a?a -i '+trailer,hashcathome)
        btexeccwd(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' '+dicthome+'/phrases.txt -r '+ruleshome+pathsep+'best64.rule --loopback '+trailer,hashcathome)
        btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+'/phrases.txt '+dicthome+'/last3.txt '+trailer,hashcathome)
        
        if dolast==1 or nuke:     
            btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+dicthome+'/phrases.txt '+dicthome+'/last4.txt '+trailer,hashcathome)

    #if we've got a dict + mask specified, they probably want this            
    if dictoverride and mask:
        rmask=mask

    if lmask:
        print("Using specified left mask and dict: "+lmask)        
        btexeccwd(hcbin+' -a7 -m '+hashtype+' '+pwdfile+' '+lmask+' '+d+' -i '+trailer+skip,hashcathome)
    else:    
        if rmask or mask:
            if mask:
                print("Using specified mask "+mask)
                if re.match('\?',mask): 
                    btexeccwd(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' '+mask+' -i '+trailer+skip,hashcathome)
                else:
                    btexeccwd(hcbin+' -a3 -m '+hashtype+' '+pwdfile+' '+mask+' '+trailer+skip,hashcathome)
            if rmask:
                print("Using specified dict + right mask: "+rmask) 
                btexeccwd(hcbin+' -a6 -m '+hashtype+' '+pwdfile+' '+d+' -i '+rmask+' '+trailer+skip,hashcathome)
        else:
            if rightdictoverride:
                #if we've got right dict override, this is a cross product (-a1) 
                print("Using specified left and right dictionaries")
                btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+d+' '+rightdictoverride+'  '+trailer+skip,hashcathome)
            else:
                #otherwise, "normal" dict + rules run
                print("Using dict and rules")        
                btexeccwd(hcbin+' -a0 -m '+hashtype+' '+pwdfile+' '+d+' -r '+r+'  --loopback '+trailer+skip,hashcathome)

                if dolast==1 or nuke:
                    btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+d+' '+dicthome+'/last3.txt '+trailer,hashcathome)

                if nuke:                    
                    btexeccwd(hcbin+' -a1 -m '+hashtype+' '+pwdfile+' '+d+' '+dicthome+'/last4.txt '+trailer,hashcathome)
                    
                
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
def run_command(command):
    p = subprocess.Popen(command.split(' '),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')

#main - read the options and do the set up for the cracking
def main():

    #needs to be run with python3
    if sys.version_info < (3,0):
        print("*** Needs python3 for utf-8 / encoding support")
        
    assert sys.version_info >= (3,0)

    #declarations

    exe='.bin'  # default to Linux for the moment 
    minlength=1 # min length for -a3 attacks
    status=''
    cachetime=3600
    maskattack=0
    
    # setup my defaults
    hashtype     = 'auto'   # autodetect
    hashcathome='hashcat-5.1.0' 
    dicthome='dict'
    ruleshome='rules'

    print("Loading config")
    try:

        config = configparser.ConfigParser()
        config.read("hashcrack.cfg")

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
    except:
        print("Error reading config files, so going with default dicts and rules")

    # declarations
    trailer=''
    dict=''
    inc=0
    mininc=1
    nuke=''
    dolast=0
    rules='best64.rule'
    colon=''
    pathstyle=''
    pathsep='/'
    fhash=''
    crib=''
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
    parser.add_argument('-c','--crib',  help='Crib file - keep it short')
    parser.add_argument('-m','--mask', help='Mask to use')
    parser.add_argument('--rmask', help='Right hand mask to use with dict')
    parser.add_argument('--lmask', help='Left hand mask to use with dict')
    parser.add_argument('-t','--type', help='Hash type')
    parser.add_argument('-d','--dict', help='Dictionary override')
    parser.add_argument('-e','--rightdict', help='Second dictionary override')
    parser.add_argument('-r','--rules', help='Rules override')
    parser.add_argument('--potfile', help='Potfile override')
    parser.add_argument('-tf','--thisfound', help='Use this instead of found.txt')
    parser.add_argument('-P','--prince', help='Use PRINCE preprocessor')
    parser.add_argument('-O','--omen', help='Use OMEN preprocessor')
    parser.add_argument('-C','--chunk', help='Use this chunk size')    
    parser.add_argument('-a','--mininc', help='Min increment')
    parser.add_argument('-z','--maxinc', help='Max increment')    
    parser.add_argument('--skip', help='Skip argument to hashcat')
    
    parser.add_argument('--restore', action="store_true", help='Restore to last session')
    parser.add_argument('-s','--show', action="store_true", help='Just show stuff')
    parser.add_argument('-l','--last', action="store_true", help='Use last3 file together with the given or default dictionary')
    parser.add_argument('-f','--found', action="store_true", help='Update found list')
    parser.add_argument('--force', action="store_true", help='Run with CPU as well. Gets you up to 8% percent extra oomph, depending on hash type')
    parser.add_argument('--remove', action="store_true", help='Remove found hashes from input file')
    parser.add_argument('-w','--words', action="store_true", help='Use words file')
    parser.add_argument('--noinc', action="store_true", help='Don not use increment')
    parser.add_argument('-p','--phrases', action="store_true", help='Use phrases file')
    parser.add_argument('-u','--username', action="store_true", help='Override username flag')
    parser.add_argument('-n','--nuke', action="store_true", help='Do more')
    
    args = parser.parse_args()

    if not args.input and not args.hash:
        die("Please specify [--input|-i] <input file> or --hash <input hash>") 
    
    infile=args.input
    show=args.show
    inhash=args.hash
    crib=args.crib

    if infile is not None:
        infile=os.path.abspath(infile)

    if crib is not None:
        crib=os.path.abspath(crib)
        
    words=args.words
    phrases=args.phrases
    mask=args.mask
    username=args.username
    dolast=args.last
    nuke=args.nuke
    skip=args.skip
    restore=args.restore
    remove=args.remove
    force=args.force
    stype=args.type
    rightdict=args.rightdict
    mininc=args.mininc
    maxinc=args.maxinc

    #todo 
    thisfound=args.found
    chunk=args.chunk
    prince=args.prince
    omen=args.omen

    p_os=platform.system()

    if re.match(r'Linux',p_os):
        pathstyle='unix'
        unix=1
        crackopts=crackopts+" -w4 "
        hashcathome='./hashcat-5.1.0'
        ruleshome='./hashcat-5.1.0/rules'
        exe='.bin'
    else:
        if re.match(r'Windows',p_os):
            if not show:
                print("Running under win32")
            exe='.exe'
            hashcathome='hashcat-5.1.0' #relative path issues with 4.10
            pathstyle='win32'
            pathsep=r'\\'
            ruleshome='hashcat-5.1.0\\rules'
        else:
            print("Unknown platform")
            exit
            

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
            
    if rightdict is not None:
        rightdict=os.path.abspath(rightdict)
        if not is_non_zero_file(rightdict):
            print("Can't find dictionary file "+rightdict)
            sys.exit(1)
            
            
    rulesoverride=args.rules

    if rulesoverride is not None:
        rulesoverride=os.path.abspath(rulesoverride)
        if not is_non_zero_file(rulesoverride):
            print("Can't find rules file "+rulesoverride)
            sys.exit(1)
        
    potfile=args.potfile
    rmask=args.rmask
    lmask=args.lmask
    noinc=args.noinc    

    if infile:
        infile=os.path.abspath(infile)
        tmpfile=infile+'.tmp'
        tmpfile2=infile+'.tmp2'
    else:
        infile=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.hash.tmp'
        tmpfile=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.tmp'
        tmpfile2=tempfile.gettempdir()+pathsep+next(tempfile._get_candidate_names())+'.tmp2'
        outfile = open(infile,'w')
        outfile.write(inhash)
        outfile.close()


    
    try:
        config = configparser.ConfigParser()
        config.read("hashcrack.cfg")
        javapath = config.get('paths', 'javapath')
        python2path = config.get('paths', 'python2path')
        python3path = config.get('paths', 'python3path')
        perlpath = config.get('paths', 'perlpath')

        hashcathome = config.get('paths', 'hc')
        ruleshome = config.get('paths', 'rules')
        dicthome = config.get('paths', 'dict')
    except:
        javapath='java'
        python2path='python'
        perlpath='perl'
        hcpath=os.path.abspath('hashcat-5.1.0')

        
    hashtype=args.type
    
    if not hashtype:
        hashtype='auto'
    else:
        #remap friendly name to numeric if need be 
        if re.match('^[a-zA-Z][a-zA-z0-9]+$',hashtype):
            hashtype=friendlymap(hashtype)
            
    found=args.found

    #grab a crib from previously found passwords
    if found:
        if not is_non_zero_file('found.txt'):
            if potfile:
                getregexpfromfile(':([^:]+)$',potfile,'found.txt',True)
            else:
                getregexpfromfile(':([^:]+)$',hashcathome+pathsep+'hashcat.potfile','found.txt',True)
        else:    
            if file_age_in_seconds('found.txt')>3600:
                if potfile and is_non_zero_file(potfile):
                    getregexpfromfile(':([^:]+)$',potfile,'found.txt',True)
                else:
                    getregexpfromfile(':([^:]+)$',hashcathome+pathsep+'hashcat.potfile','found.txt',True)
            
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
               '13100':0,
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
                    
    if not show:
        print("Cracking "+ hashtype + " type hashes")
    
    hcbin=hashcathome+pathsep+r'hashcat64'+exe

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

        # jks - invoke a subprocess to build the compatible file     
        if stype=='jks':
            btexeccwd(javapath+' -jar JksPrivkPrepare.jar '+infile+' > '+tmpfile)
            
            hashtype='15500'
            
            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc
            
            runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke , found, potfile, noinc, show, skip, restore, force, remove)  

        # ifm - ntsdutil zipped output
        if stype=='ifm':
            
            tdir=tempfile.gettempdir()

            zip_file = zipfile.ZipFile(infile, 'r')
            
            for member in zip_file.namelist():
                filename = os.path.basename(member)
                # skip directories
                if not filename:
                    continue
                
                # copy file (taken from zipfile's extract)
                source = zip_file.open(member)
                target = open(os.path.join(tdir, filename), "wb")
                with source, target:
                    shutil.copyfileobj(source, target)
                    
                target.close()
                source.close()
                
            zip_file.close()

            #check for existence of "sam.reg"

            sam = tdir+pathsep+"sam.reg"
            
            if is_non_zero_file(sam):  
           
                btexec(python2path+' impacket/examples/secretsdump.py -system '+tdir+pathsep+'system.reg -security '+tdir+pathsep+'security.reg  -sam '+tdir+pathsep+'sam.reg LOCAL -outputfile '+tmpfile)
                
                infile=tmpfile+'.sam'

                if not is_non_zero_file(infile):
                    print("Failed to generate sam file - check impacket setup, and python2")
                    sys.exit(1)

                #also cached creds 
                    
            else:
                btexec(python2path+' impacket/examples/secretsdump.py -system '+tdir+pathsep+'SYSTEM  -ntds '+tdir+pathsep+'ntds.dit LOCAL -outputfile '+tmpfile) 

                infile=tmpfile+'.ntds'
            
                if not is_non_zero_file(infile):
                    print("Failed to generate ntds file - check impacket setup, and python2")
                    sys.exit(1)
                    
            hashtype='1000'
            stype='pwdump'     # fall through to pwdump processing now, cos that's what we've got
            
        #pwdump - do the LM stuff for cribs and then all case permuatations of that. then normal crack
        if stype=='pwdump':
            if not show:
                btexeccwd(hcbin+' -a3 -m 3000 '+infile+' ?a?a?a?a?a?a?a -i '+trailer,hashcathome)
                btexeccwd(hcbin+' -a3 -m 3000 '+infile+' ?a?a?a?a?a?a?a --show --quiet -o '+tmpfile,hashcathome)
                
                inpfile = open(tmpfile,'r')
                outfile = open(tmpfile2,'w')
                
                with open(tmpfile) as inp:
                    for l in inp:
                        m = re.search(':([^:]+)$', l)
                        ans=m.group(1)
                        outfile.write(ans)                        
                
                inpfile.close()
                outfile.close()

                hashtype='1000'
            
                btexeccwd(hcbin+' -a0 -m '+hashtype+' '+infile+' '+tmpfile2+' -r rules/allcase.rule '+trailer,hashcathome)

            hashtype='1000'

            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc

            runhc(hashcathome, infile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)

        #7z
        if stype=='7z':
            btexec(perlpath+' john/run/7z2john.pl '+infile+' > '+tmpfile)
            
            hashtype='11600'

            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc

            runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)  

        #ms office, various subtypes
        if stype=='msoffice':
            btexec(python2path+' john/run/office2john.py '+infile+' > '+tmpfile)
            #get cut -f 2 colon
            getregexpfromfile('[^ :]:(.+)',tmpfile,tmpfile2,False)

            wordver=getfirstline(tmpfile2)

            hashtype="null"

            if re.match(r'\$office\$\*2013',wordver):
                hashtype='9600'

            if re.match(r'\$office\$\*2007',wordver):
                hashtype='9400'

            if re.match(r'\$office\$\*2010',wordver):
                hashtype='9500'

            if re.match(r'\$oldoffice\$\*0',wordver):
                hashtype='9700'

            if re.match(r'\$oldoffice\$\*3',wordver):
                hashtype='9800'

            if hashtype=='null':
                print("Failed to  file - check python2 and jtr path - specifically john/run/office2john.py")
                sys.exit(1)
                
                
            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc

            runhc(hashcathome, tmpfile2, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)


        #PDF, various subtypes
        if stype=='pdf':
            btexec(perlpath+' john/run/pdf2john.pl '+infile+' > '+tmpfile)
            #get cut -f 2 colon
            getregexpfromfile('[^ :]:(.+)',tmpfile,tmpfile2,False)

            pdfver=getfirstline(tmpfile2)

            hashtype='null'

            if re.match(r'\$pdf\$1\*',pdfver):
                hashtype='10400'

            if re.match(r'\$pdf\$2\*3',pdfver):
                hashtype='10500'

            if re.match(r'\$pdf\$4\*',pdfver):
                hashtype='10500'

            if re.match(r'\$pdf\$5\*5',pdfver):
                hashtype='10600'

            if re.match(r'\$pdf\$5\*6',pdfver):
                hashtype='10700'

            if hashtype=='null':
                print("Failed to  file - check perl and jtr path - specifically john/run/pdf2john.pl")
                sys.exit(1)
                

            (dict,rules,inc)=selectparams( hashtype, nuke, ruleshome, dicthome )

            if maxinc is not None:
                inc=maxinc

            runhc(hashcathome, tmpfile2, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)
            
            
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
            
                runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)
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
                
                runhc(hashcathome, tmpfile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)
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
        
        runhc(hashcathome, infile, hashtype, dict, rules, inc, trailer, dicthome, dictoverride, rightdict, rulesoverride, mask, lmask, rmask, dolast, ruleshome, words, pathsep, exe, crib, phrases, username, nuke, found, potfile, noinc, show, skip, restore, force, remove)
  
if __name__== "__main__":
  main()


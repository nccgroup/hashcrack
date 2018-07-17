# hashcrack
unpacks some hash types, picks sensible options and invokes hashcat

NVIDIA drivers here: http://www.nvidia.co.uk/Download/index.aspx?lang=en-uk

# python version

To install: python3 setup.py

This will fetch about 30Gb of dictionaries

To run- various cases:

Bog standard crack:
python3 empiricist.py -i <input file>
or:
python3 empiricist.py --hash <literal hash>

Try harder - use words and phrases and previously found passwords 
python3 empiricist.py --input <input file> --words --phrases --found

Nuclear option - use bigger rules + dict
python3 empiricist.py --input <input file> --nuke

Try a bunch of dumb passwords:
python3 empiricist.py -i <input file> --crib dict/dumb.txt

Try a bunch of dumb passwords part 2:
python3 empiricist.py -i <input file> --mask default.hcmask

Try your own mask:
python3 empiricist.py -i <input file> --mask ?l?l?l?l?l?l

Run an IFM dump you've saved as a zip:
python3 empiricist.py -i <input file.zip> [-t ifm] 

See also test.bat

Input file may be a docx, pdf, JKS file, etc.


See also crackstation dictionaries - https://crackstation.net/







===

Thanks to https://github.com/berzerk0 for some wordlists - these are CC licensed. See:  https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords

Other wordlists used are openwall_all.txt from Solar Designer, a crack of 275mil of Troy Hunt's hashes, and breachcompilation.txt - origin unknown. (Have merged the last two.)

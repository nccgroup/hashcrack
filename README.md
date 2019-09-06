# hashcrack
unpacks some hash types, picks sensible options and invokes hashcat

NVIDIA drivers here: http://www.nvidia.co.uk/Download/index.aspx?lang=en-uk

alt email: jamie@blacktraffic.co.uk if you need support

I'm not sure if anyone at NCC will be looking after this, but I'll be doing active dev in this branch in future: https://github.com/jamieriden/hashcrack

# python version

To install:

    pip3 install -r requirements.txt
    python3 setup.py

If you don't have Python in your path:

    <path to python>/python.exe -m pip install -r requirements.txt
    <path to python>/python.exe setup.py

This will fetch about 30Gb of dictionaries - YOU HAVE BEEN WARNED

for 7z files, you will need perl and Compress::Raw::LZMA, so maybe one of these two depending on your perl distribution: 

ActiveState Perl:

    ppm install Compress::Raw::LZMA

Strawberry Perl:

    cpan install Compress::Raw::LZMA

To run - various cases:

Bog standard crack:

    python3 hashcrack.py -i <input file>

or:

    python3 hashcrack.py --hash <literal hash>

Try harder - use words and phrases and previously found passwords 

    python3 hashcrack.py --input <input file> --words --phrases --found

Nuclear option - use bigger rules + dict

    python3 hashcrack.py --input <input file> --nuke

Try a bunch of dumb passwords:

    python3 hashcrack.py -i <input file> --crib dict/dumb.txt

Try a bunch of dumb passwords part 2:

    python3 hashcrack.py -i <input file> --mask default.hcmask

Try your own mask:

    python3 hashcrack.py -i <input file> --mask ?l?l?l?l?l?l

Run an IFM dump you've saved as a zip:

    python3 hashcrack.py -i <input file.zip> [-t ifm] 

See also test.bat

Input file may be a docx, pdf, JKS file, etc.


See also crackstation dictionaries - https://crackstation.net/


If you don't have Perl/Python/Java in your path, can set the correct paths in `hashcrack.cfg` - these are the paths to the executable files, rather than the directory the executable is in.




===

Thanks to https://github.com/berzerk0 for some wordlists - these are CC licensed. See:  https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords

Other wordlists used are openwall_all.txt from Solar Designer, a crack of 275mil of Troy Hunt's hashes (mine), and breachcompilation.txt - origin unknown. (Have merged the last two.)

Includes https://www.7-zip.org/ code - which is LGPL. Thanks all! 

nsav2dive.rule is from here - thanks! https://github.com/NSAKEY/nsa-rules

License for nsav2dive.rule:

The Fair License

Copyright (c) 2015 _NSAKEY

Usage of the works is permitted provided that this instrument is retained with the works, so that any entity that uses the works is notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

Special thanks to CMIYK competition and hashes.org for test data.

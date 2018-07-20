REM start tests

REM postgres
python3 hashcrack.py -i tests/postgres.txt --force

python3 hashcrack.py -i tests/postgres.txt --show

REM  autodetect - answer is "foo"
python3 hashcrack.py --hash 0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
python3 hashcrack.py --hash 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
python3 hashcrack.py --hash f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7
python3 hashcrack.py -i tests/dollar1.txt
python3 hashcrack.py -i tests/apachemd5.txt

REM  ifm
python3 hashcrack.py -i tests/ifm.zip -t ifm

REM 7z
python3 hashcrack.py -i tests/test.7z

REM  autodetect - answer is "cisco"
python3 hashcrack.py --hash 2KFQnbNIdI.2KYOU

REM sha1
python3 hashcrack.py -i tests/sha1.txt

REM keystore
python3 hashcrack.py -i tests/keystore.jks

REM  autodetect - hashcat example hashes where the answer is "hashcat"
python3 hashcrack.py -i tests/sha256crypt.txt -d hashcat.txt
python3 hashcrack.py -i tests/sha512crypt.txt -d hashcat.txt

REM autodetect PDF 
python3 hashcrack.py -i tests/test-hashcat.pdf -d hashcat.txt

REM autodetect Word 
python3 hashcrack.py -i tests/test-abc.docx -d hashcat.txt

REM  oracle 7
python3 hashcrack.py --hash "7A963A529D2E3229:3682427524"

REM  oracle 11
python3 hashcrack.py --hash "ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130"

REM  oracle 12+
python3 hashcrack.py --hash "78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225" -t 12300 -d hashcat.txt

REM mssql 2000
python3 hashcrack.py --hash "0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578" -t 131

REM mssql 2005
python3 hashcrack.py --hash "0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe" -t 132

REM netlmv1
python3 hashcrack.py --hash "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c" 

REM netlmv2
python3 hashcrack.py --hash "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030"

python3 hashcrack.py --hash "b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef"


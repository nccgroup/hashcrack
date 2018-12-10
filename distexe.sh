cmd /c 'python3.exe setupexe.py build_exe'
rm -f hashcrackwin.zip
zip -r hashcrackwin.zip build
rsync --partial --progress hashcrackwin.zip root@zealot:/var/www/html/


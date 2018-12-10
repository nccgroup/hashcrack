rm -rf build
touch setupexe.py
cmd /c 'python3.exe setupexe.py build_exe'
rm -f hashcrackwin.zip
zip -r hashcrackwin.zip build
rsync --partial --progress hashcrackwin.zip root@zealot:/var/www/html/
cd build/exe.win-amd64-3.6 ; cmd /c "hashcrackwin.exe -i kerb7500.txt" ; cd ../..


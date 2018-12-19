rm -rf build
touch setupexe.py
cmd /c 'python3.exe setupexe.py build_exe'
rm -f hashcrackwin.zip
rm -rf hashcrackwin
mv build/exe.win-amd64-3.6 hashcrackwin
zip -r hashcrackwin.zip hashcrackwin
cd hashcrackwin ; cmd /c "hashcrackwin.exe -i kerb7500.txt" ; cd ..
cd hashcrackwin ; cmd /c "hashcrackwin.exe -i netlmv2.txt" ; cd ..
rsync --partial --progress hashcrackwin.zip root@zealot:/var/www/html/

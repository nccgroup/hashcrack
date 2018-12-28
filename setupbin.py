#setup.py
import sys, os
from cx_Freeze import setup, Executable

__version__ = "1.0.1"

include_files = ['regmap.cfg','hashcrack.cfg','map.cfg','quickmap.cfg','rules/l33tnsa.rule','rules/leet2.rule','rules/l33tpasspro.rule','rules/l33t64.rule','rules/best64.rule','rules/null.rule','dict/Top95Thousand-probable.txt','dict/words.txt','tests/kerb7500.txt','dict/last3.txt','dict/phrases.txt','dict/last4.txt','graph-pw-by-length.py']

# ,'dict/Top258Million-probable.txt','dict/Top32Million-probable.txt','cracked-passwords.txt']
excludes = ["tkinter"]
packages = ["cx_freeze", "re", "base64", "os","sys","sqlite3","shutil","argparse","urllib","zipfile","tempfile","time","stat","configparser","platform"]

setup(
    name = "hashcrack",
    description='Password cracking helper',
    version=__version__,
    options = {"build_exe": {
    'packages': packages,
    'include_files': include_files,
    'excludes': excludes,
    'include_msvcr': True,
}},
executables = [Executable("hashcrack.py",base=None)]
)

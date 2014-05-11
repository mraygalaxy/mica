MICA: Memory-Interposed Chinese Assistant
=========================================

MICA is a language-learning memory-assisted software program
for Chinese that tracks what words you know and don't know
as you read through stories. The motivation is that there are
already oceans of pre-existing chinese authors and internet
content out there, so why not use it for language learning
(even beginners), rather than depend on communities of people
and/or flashcards to bootstrap the content of the language
software - let's teach people to read what already exists
in the world, and then use people to correct the errors
*after* the content has already been tranformed into an
interactive, readable format.

Full Usage Documentation: https://github.com/hinesmr/mica/wiki

Credits:
 1. Lexical word parsing and character grouping: http://www.ictclas.org
 2. Offline chinese translation: https://pypi.python.org/pypi/cjklib
 3. Offline polyphome listings: https://github.com/lxyu/pinyin
 4. Online sentence-level translations: http://www.microsoft.com/en-us/translator/ (as long as it remains free)
 5. PDF extraction: pdfminer
 6. PDF creation: fpdf


INSTALLATION:
=============

There are several steps to perform before MICA can run:

(Yes, please follow them all).

1) Install basic package dependencies

$ sudo apt-get install python-dev python-openssl python-setuptools python-sqlalchemy python-twisted* python-beaker python-webob libstdc++5 python-simplejson python-daemon python-pip python-crypto python-zodb

2) Create a developer account / Translator Application key/ID requests from Microsoft

$ https://datamarket.azure.com/account/keys # create keys

$ http://datamarket.azure.com/dataset/bing/microsofttranslator # bind those keys to the translator API

 # You might need to create a couple of new accounts - just follow the instructions

3) Install CJK library and CEDICT:

$ cd /tmp

$ sudo pip install cjklib  # not yet in apt-get

$ sudo installcjkdict CEDICT

$ wget ftp://ftp.unicode.org/Public/UNIDATA/Unihan.zip

$ sudo buildcjkdb -r build cjklibData 


4) Generated a self-signed certificate for Twisted

$ openssl req -x509 -nodes -days 9000 -newkey rsa:2048 -keyout mica.key -out mica.crt

5) Copy ICTC (www.ictclas.org) libraries for linking 

$ sudo cp ictc_64bit/libICTCLAS50.* /usr/lib64  # if you are on a 64-bit system

$ sudo cp ictc_32bit/libICTCLAS50.* /usr/lib    # if you are on a 32-bit system

$ sudo ldconfig

6) Compile Python Interface to Beijing University ICTCLAS Chinese Lexical Analysis System 
 
$ cd mica

$ python setup.py build

$ sudo python setup.py install 

$ cp build/*/mica_ictclas.so .

7) Install PDF manipulation libraries:

$ sudo pip install pdfminer
$ sudo pip install fpdf


RUNNING:
========

If all the dependencies are in place, then you should be able to do the following:

$ ./mica.py -I client_id -S client_key_long_string_of_characters -C path_to_cacert -K path_to_private_key

   # Where the first to 'I' and 'S' parameters are the ID and key you got from the microsoft translation free application developer accounts and the last two parameters 'C' and 'K' are from the openssl command from above if you needed to needed to create a self-signed certificate.

   # You can add the '-k' option if you want to restart the process without throwing away all the cookies used in the web interfaces in case you want to easily update the software.

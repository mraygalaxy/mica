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

Full Documentation & Usage & Motivation:

https://github.com/hinesmr/mica/wiki

INSTALLATION:
=============

There are several steps to perform before MICA can run:

1. apt-get install basic package dependencies
2. Build a python interface to the Beijing University ICTLAS Lexical Analysis System
3. Create a Microsoft Translation developer account and register an application
   (Why not Google? Because its not free anymore, and microsoft still is).
4. Install CJK Lib and CEDICT
5. Generate a self-signed SSL certificate for the main user interface (over twisted)
   (or use your own).

DETAILED INSTRUCTIONS:
======================
Getting Started:

1. Install basic package dependencies

$ apt-get install python-dev python-openssl python-setuptools python-sqlalchemy python-twisted* python-beaker python-webob libstdc++5 python-simplejson python-daemon python-pip

 # (yes, they are all required as of now)

2. Compile Python Interface to Beijing University ICTCLAS Chinese Lexical Analysis System 
 
$ cd mica

$ python setup.py build

$ cp build/*/mica.so .

3. Create a developer account / Translator Application key/ID requests from Microsoft

$ https://datamarket.azure.com/account/keys # create keys

$ http://datamarket.azure.com/dataset/bing/microsofttranslator # bind those keys to the translator API

 # You might need to create a couple of new accounts - just follow the instructions

4. Install CJK library and CEDICT:

$ cd /tmp

$ pip install cjklib  # not yet in apt-get

$ sudo installcjkdict CEDICT

$ wget ftp://ftp.unicode.org/Public/UNIDATA/Unihan.zip

$ sudo buildcjkdb -r build cjklibData 


5. Generated a self-signed certificate for Twisted

$ openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

RUNNING:
========

If all the dependencies are in place, then you should be able to do the following:

$ ./mica.py -I client_id -S client_key_long_string_of_characters -C path_to_cacert -K path_to_private_key

 # You can add the '-k' option if you want to restart the process without throwing away 
 
 # all the cookies used in the web interfaces in case you want to easily update the software.

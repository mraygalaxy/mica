mica
====

MICA: Memory-interposed Chinese Assistant

Software Used:

Getting Started:

# Compile Python Interface to Beijing University ICTCLAS Chinese Lexical Analysis System 
# http://www.ictclas.org/

cd mica
apt-get install python-dev
python setup.py build
cp build/*/mica.so .

# Create a developer account / Translator Application key/ID requests from Microsoft
# Why Microsoft and not google? Because it's still free.

# Generated a self-signed certificate for Twisted
openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

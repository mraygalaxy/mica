#!/bin/bash

# service ssh start debugging, only

ip=$(ip addr show eth0 | grep inet | sed -e "s/ \+/ /g" | head -1 | cut -d " " -f 3 | sed -e "s/\/.*//g")
echo "initializing couch node name with: couchdb@${ip}"

sed -ie "s/-name .*/-name couchdb@${ip}/g" /usr/local/lib/couchdb/etc/vm.args

# Upon creation of the base container, couchdb remembers it's previous identity, and the only
# way to make it forget is to blow away the data.
rm -rf /usr/local/lib/couchdb/data/*

service couchdb start

sleep 5
echo "Rebinding..."

curl -X PUT http://127.0.0.1:5984/_node/couchdb@${ip}/_config/chttpd/bind_address -d '"0.0.0.0"'
curl -X PUT http://127.0.0.1:5984/_node/couchdb@${ip}/_config/httpd/bind_address -d '"0.0.0.0"'

bash

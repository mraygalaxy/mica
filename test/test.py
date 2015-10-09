#!/usr/bin/env python

from docker import Client
from json import loads as json_loads, dumps as json_dumps
import requests

c = Client(base_url='unix://var/run/docker.sock')

#print str(c.inspect_container("couchdev"))

s = requests.Session()

r = s.get("http://localhost")
assert(r.status_code == 200)

r = s.post("http://localhost/connect", data=dict(human='0', username='family@hinespot.com', password='Iamtwo34', remember='on', address='http://localhost:5984', connect='1'))
assert(r.status_code == 200)
assert(json_loads(r.text)['success'])

r = s.get("http://localhost/disconnect")
assert(r.status_code == 200)

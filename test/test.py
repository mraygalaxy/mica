#!/usr/bin/env python

from docker import Client

c = Client(base_url='unix://var/run/docker.sock')

print str(c.inspect_container("couchdev"))

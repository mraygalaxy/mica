#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, flattenString
from twisted.python.filepath import FilePath
from twisted.internet import defer
from common import *
import os
import re

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

class InfoElement(Element):
    loader = XMLFile(FilePath(cwd + 'serve/info_template.html'))

    widgetData = ['gadget', 'contraption', 'gizmo', 'doohickey']

    @renderer
    def widgets(self, request, tag):
        for widget in self.widgetData:
            yield tag.clone().fillSlots(widgetName=widget)

class HeadElement(Element):
    def __init__(self, req) :
        super(HeadElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/head_template.html'))

    @renderer
    def pull(self, request, tag):
         sub = self.req.db.pull_percent() if self.req.db else "WORKED"
         return tag(sub)

@defer.inlineCallbacks
def run_template(req, which) :
    d = flattenString(None, which(req))
    d.addErrback(mdebug)
    req.flat = yield d 

#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, flattenString
from twisted.python.filepath import FilePath
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

def printResult(result):
    print result

flattenString(None, WidgetsElement()).addCallback(printResult)

#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, flattenString, tags
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

'''
class NavElement(Element) :
    loader = XMLFile(FilePath(cwd + 'serve/nav_template.html'))
'''

class HeadElement(Element):
    def __init__(self, req) :
        super(HeadElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/head_template.html'))

    menu = [ 
             ("home" , ("/home", "home", _("Review"))), 
             ("edit" , ("/edit", "pencil", _("Edit"))), 
             ("read" , ("/read", "book", _("Read"))), 
        ]

    @renderer
    def headnavparent(self, request, tag) :
        if not self.req.session.value['connected'] :
            return tag("")

        navcontents = ""
        navactive = self.req.action

        if navactive == 'home' or navactive == 'index' :
            navactive = 'home'

        for (key, value) in self.menu :
            (url, icon, display) = value 
            itag = tags.i(**{"class":'glyphicon glyphicon-' + icon})
            if navactive == key :
                atag = tags.a(href=url)(itag, " ", display)
                itemtag = tags.li(**{"class":"active"})
                tag(itemtag(atag))
            else :
                atag = tags.a(href=url)(itag, " ", display)
                tag(tags.li(atag))

        return tag
        '''
        if self.req.pretend_disconnected :
            return tag

            navcontents += """
                             <li class='dropdown'>
                             <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                           """
            navcontents += "<i class='glyphicon glyphicon-user'></i>&nbsp;" + _("Account") + "&nbsp;<b class='caret'></b>"
            navcontents += """
                             </a>
                             <ul class='dropdown-menu'>
                            """
            if not self.req.mobile :
                navcontents += "<li><a href='#uploadModal' data-toggle='modal'><i class='glyphicon glyphicon-upload'></i>&nbsp;Upload New Story</a></li>"

                if self.req.user and 'admin' in self.req.user['roles'] :
                    navcontents += "<li><a href='#newAccountModal' data-toggle='modal'><i class='glyphicon glyphicon-plus-sign'></i>&nbsp;New Account</a></li>"

            navcontents += """
                <li><a href='/account'><i class='glyphicon glyphicon-user'></i>&nbsp;Preferences</a></li>
                <li><a onclick='switchlist()' href='#'><i class='glyphicon glyphicon-tasks'></i>&nbsp;<div id='switchlisttext' style='display: inline'></div></a></li>
                <li><a href='/disconnect'><i class='glyphicon glyphicon-off'></i>&nbsp;Disconnect</a></li>
                <li><a href='#aboutModal' data-toggle='modal'><i class='glyphicon glyphicon-info-sign'></i>&nbsp;About</a></li>
                <li><a href='/help'><i class='glyphicon glyphicon-question-sign'></i>&nbsp;Help</a></li>
                <li><a href='/privacy'><i class='glyphicon glyphicon-lock'></i>&nbsp;Privacy</a></li>
                </ul>
                </li>
            """
        return tag(navcontents)
        '''
    @renderer
    def pull(self, request, tag):
        return tag(self.req.db.pull_percent() if self.req.db else "")

    @renderer
    def push(self, request, tag):
        return tag(self.req.db.push_percent() if self.req.db else "")

    @renderer
    def views(self, request, tag) :
        return tag(self.req.view_percent)

    @renderer
    def scriptpopover(self, request, tag) :
        popoveractivate = "$('#connectpop').popover('show');"
        return tag(popoveractivate if (not self.req.session.value["connected"] and not self.req.skip_show and not self.req.pretend_disconnected) else "")

    @renderer
    def scriptswitch(self, request, tag) :
         return tag("" if not self.req.session.value["connected"] else ("switchinstall(" + ("true" if ('list_mode' in self.req.session.value and self.req.session.value['list_mode']) else "false") + ");\n"))

    @renderer
    def cloudname(self, request, tag) :
        if self.req.session.value['connected'] and not self.req.pretend_disconnected :
            bootcanvastoggle = "togglecanvas()"
        else :
            bootcanvastoggle = ""

        tag.fillSlots(toggle = bootcanvastoggle)

        if not self.req.session.value['connected'] :
            return tag(tags.img(id = "connectpop", src='MSTRAP/favicon.ico', width='20px'))
        else :
            return tag(tags.img(src='MSTRAP/favicon.ico', width='20px'))

        return tag

    @renderer
    def remember(self, request, tag) :
        if 'last_remember' in self.req.session.value :
            return tag(tags.input(type='checkbox', name='remember', checked='checked'))
        else :
            return tag(tags.input(type='checkbox', name='remember'))

    @renderer
    def head(self, request, tag):
        zoom_level = 1.0

        if self.req.mobile :
            if "default_app_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_app_zoom"]
        else :
            if "default_web_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_web_zoom"]

        return tag(tags.meta(name="viewport", content="width=device-width, initial-scale=" + str(zoom_level)))

    @renderer
    def address(self, request, tag) :
       return tag(tags.input(type="text", id="address", name="address", placeholder="Address", value=self.req.address))

    @renderer
    def username(self, request, tag) :
       user = self.req.session.value['last_username'] if 'last_username' in self.req.session.value else ''
       return tag(tags.input(type="text", id="username", name="username", placeholder="Username", value=user))

    @renderer
    def allslots(self, request, tag) :
       tag.fillSlots(jquery = self.req.bootstrappath + "/js/jquery.js",
                     bootminjs = self.req.bootstrappath + "/js/bootstrap.min.js",
                     bootmincss = self.req.bootstrappath + "/css/bootstrap.min.css",
                     micacss = self.req.mpath + "/mica.css",
                     micajs = self.req.mpath + "/mica.js",
                     bootpagejs = self.req.bootstrappath + "/js/jquery.bootpag.min.js",
                     )
       return tag


@defer.inlineCallbacks
def run_template(req, which) :
    d = flattenString(None, which(req))
    d.addErrback(mdebug)
    req.flat = yield d 

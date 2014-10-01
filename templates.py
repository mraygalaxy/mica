#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, flattenString, tags, XMLString
from twisted.python.filepath import FilePath
from twisted.internet import defer
from common import *
import os
import re

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

bootlangs = ""
for l, readable in lang.iteritems() :
    bootlangs += "<option value='" + l + "'>" + readable + "</option>\n"

class StaticNavElement(Element) :
    loader = XMLFile(FilePath(cwd + 'serve/nav_template.html'))

    @renderer
    def accountslots(self, request, tag) :
        tag.fillSlots(preferences = _("Preferences"),
                      disconnect = _("Disconnect"),
                      about = _("About"),
                      help = _("Help"),
                      privacy = _("Privacy"))
        return tag

class EditHistoryElement(Element) :
    def __init__(self, req) :
        super(EditHistoryElement, self).__init__() 
        self.req = req

    loader = XMLString("<html xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='edit_history'/>")

    @renderer
    def edit_history(self, request, tag) :
        if self.req.list_mode :
            if len(self.req.history) != 0 :
                div = tags.div(**{"class" : "panel-group", "id" : "panelEdit"})
                
                for x in self.req.history :
                    idiv = tags.div(**{"class" : "panel panel-default"})
                    iidiv = tags.div(**{"class" : "panel-heading"})

                    char, total, spy, result, tid, op = x
                    tid = str(tid)

                    if len(result) :
                        if result[0] == '/' :
                           result = result[1:-1]
                        else :
                            memberlist = tags.table(**{"class" : "table"})
                            for row in result :
                                memberlist(tags.tr(tags.td(row[0]), tags.td(row[1])))
                            result = memberlist

                    a = tags.a(**{"class" : "panel-toggle", "style" : "display: inline", "data-toggle" : "collapse", "data-parent" : "#panelEdit", "href": "#collapse" + tid})
                    i = tags.i(**{"class" : "glyphicon glyphicon-arrow-down", "style" : "50%"})
                    a(i, " ", spy)

                    if op == "SPLIT" :
                        opstr = tags.div(style="color: blue; display: inline")(_("SPLIT") + "   ")
                    else :
                        opstr = tags.div(style="color: red; display: inline")(_("MERGE") + "   ")
                    iidiv(opstr, " (" + str(total) + "): " + char + ": ", a)
                    idiv(iidiv)
                    cdiv = tags.div(**{"class" : "panel-body collapse", "id" : "collapse" + tid})
                    icdiv = tags.div(**{"class" : "panel-inner"})
                    icdiv(result)
                    cdiv(icdiv)
                    div(idiv, cdiv)
                tag(div)
            else :
                tag(tags.h4(_("No edit history available.")))
        else :
            tag(tags.h4(_("Edit list Disabled.")))

        return tag

class EditHeaderElement(Element) :
    def __init__(self, req) :
        super(EditHeaderElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/edit_header_template.html'))

    @renderer
    def edit_header(self, request, tag) :
        tag.fillSlots(editname = _("Edit Legend"),
                      processedits = self.req.process_edits,
                      retrans = self.req.retrans,
                      previousmerge = _("These characters were previously merged into a word"),
                      previoussplit = _("This word was previously split into characters"),
                      tryrecco = _("Try Recommendations"),
                      repage = _("Re-translate page"))
        return tag

class EditElement(Element) :
    def __init__(self, req) :
        super(EditElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/edit_template.html'))

    @renderer
    def edit(self, request, tag) :
        tag(EditHeaderElement(self.req))
        tag(EditHistoryElement(self.req))
        return tag

class LegendElement(Element) :
    def __init__(self, req) :
        super(LegendElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/legend_template.html'))

    @renderer
    def legend(self, request, tag) :
        tag.fillSlots(title = _("Polyphome Legend"),
                      legend1 = _("Correct for tone and meaning"),
                      legend1post = _("(No review necessary)"),
                      legend2 = _("Possibly wrong meaning"),
                      legend2post = _("(but tone is correct)"),
                      legend3 = _("Possibly wrong tone"),
                      legend3post = _("(as well as meaning)"),
                      legend4 = _("Definitely wrong previously"),
                      history = _("Polyphome Change History"))
        return tag

class DynamicViewElement(Element) :
    def __init__(self, req) :
        super(DynamicViewElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/dynamic_view_template.html'))

    @renderer
    def dynamic_view(self, request, tag) :
        uuid = 'bad_uuid'

        splits = "process_edits('"
        merges = "process_edits('"

        if "current_story" in self.req.session.value :
            uuid = self.req.session.value["current_story"]

        splits += uuid
        merges += uuid
        splits += "', 'split', false)"
        merges += "', 'merge', false)"

        tag.fillSlots(processsplits = splits, processmerges = merges)
        return tag

class StaticViewElement(Element) :
    def __init__(self, req) :
        super(StaticViewElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/static_view_template.html'))

    @renderer
    def static_view(self, request, tag) :
        tclasses = dict(text = "", images = "", both = "")

        for which, unused in tclasses.iteritems() :
            if "view_mode" in self.req.session.value :
                 if self.req.session.value["view_mode"] == which :
                     tclasses[which] += "active "

            tclasses[which] += "btn btn-default"

        onclick = "process_instant(" + ("true" if self.req.gp.already_romanized else "false") + ")"

        tag.fillSlots(textclass = tclasses["text"],
                      imageclass = tclasses["images"],
                      bothclass = tclasses["both"],
                      processinstant = onclick,
                      )

        return tag

class ViewElement(Element) :
    def __init__(self, req) :
        super(ViewElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/view_template.html'))

    @renderer
    def topview(self, request, tag) :
        stats = ""

        if self.req.action in ["read"] :
            stats = tags.div(id='memolist')
        elif self.req.action == "edit" :
            stats = tags.div(id='editslist')
        elif self.req.action == "home" :
            stats = LegendElement(self.req)

        tag.fillSlots(storyname = self.req.story_name.replace("_", " "),
                      spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                      stats = stats,
                      installpages = self.req.install_pages,
                      performingtranslation=_("Doing online translation..."),
                      go = _("Go"))
        
        return tag

    @renderer
    def view(self, request, tag) :
        tag(StaticViewElement(self.req))
        if self.req.action == "edit" :
            tag(DynamicViewElement(self.req))
        return tag

class HeadElement(Element):
    def __init__(self, req) :
        super(HeadElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/head_template.html'))

    @renderer
    def languages(self, request, tag) :
        for l, readable in lang.iteritems() :
            option = tags.option(value=l)
            tag(option(_(readable)))
        return tag

    @renderer
    def headnavparent(self, request, tag) :
        if not self.req.session.value['connected'] :
            return tag("")

        navcontents = ""
        navactive = self.req.action

        if navactive == 'home' or navactive == 'index' :
            navactive = 'home'

        menu = [ 
                 ("home" , ("/home", "home", _("Review"))), 
                 ("edit" , ("/edit", "pencil", _("Edit"))), 
                 ("read" , ("/read", "book", _("Read"))), 
            ]

        for (key, value) in menu :
            (url, icon, display) = value 
            itag = tags.i(**{"class":'glyphicon glyphicon-' + icon})
            if navactive == key :
                atag = tags.a(href=url)(itag, " ", display)
                itemtag = tags.li(**{"class":"active"})
                tag(itemtag(atag))
            else :
                atag = tags.a(href=url)(itag, " ", display)
                tag(tags.li(atag))

        if not self.req.pretend_disconnected :
            itemtag = tags.li(**{"class" : "dropdown"})
            atag = tags.a(**{"class" : "dropdown-toggle", "data-toggle" : "dropdown", "href" : "#"})
            atag(tags.i(**{"class" : "glyphicon glyphicon-user"}), " " + _("Account") + " ", tags.b(**{"class" : "caret"}))
            utag = tags.ul(**{"class" : "dropdown-menu"})

            if not self.req.mobile :
                ttag = tags.a(**{"data-toggle" : "modal", "href" : "#uploadModal"})
                ttag(tags.i(**{"class" : "glyphicon glyphicon-upload"}), " " + _("Upload New Story"))
                utag(tags.li(ttag))

                if self.req.user and 'admin' in self.req.user['roles'] :
                    ttag = tags.a(**{"data-toggle" : "modal", "href" : "#newAccountModal"})
                    ttag(tags.i(**{"class" : "glyphicon glyphicon-plus-sign"}), " " + _("New Account"))
                    utag(tags.li(ttag))

            utag(StaticNavElement())
            tag(itemtag(atag, utag))
        return tag
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
            return tag(tags.img(id = "connectpop", src=self.req.mpath + '/favicon.ico', width='20px'))
        else :
            return tag(tags.img(src=self.req.mpath + '/favicon.ico', width='20px'))

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

def load_template(req, which) :
    run_template(req, which)
    return req.flat

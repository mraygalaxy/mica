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
    if processor_map[l] :
        bootlangs += "<option value='" + l + "'>" + readable + "</option>\n"

class StoryElement(Element) :
    def __init__(self, req, content) :
        super(StoryElement, self).__init__(XMLString("<html xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='story'>" + content + "</html>")) 
        self.req = req

    @renderer
    def story(self, request, tag) :
        tag.fillSlots(notreviewed = _("Not Reviewed"),
                      reading = _("Reading"),
                      untranslated = _("Untranslated"),
                      finished = _("Finished"),
                      stories = _("Stories"))
        return tag

class PasswordElement(Element) :
    def __init__(self, req) :
        super(PasswordElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/changepass_template.html'))

    @renderer
    def password(self, request, tag) :
        tag.fillSlots(oldpassword =_("Old Password"),
                      password = _("New Password"),
                      confirm = _("Confirm Password"),
                      change = _("Change Password"),
                      microsoft = _("Input Microsoft Translation API Credentials?"),
                      request = _("You can request free credentials"),
                      going = _("by going here")
                      )
        return tag

class HistoryElement(Element) :
    def __init__(self, req) :
        super(HistoryElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/history_template.html'))

    @renderer
    def history(self, request, tag) :
        tag.fillSlots(onlineoffline = self.req.onlineoffline)
        return tag

    @renderer
    def panel(self, request, tag) :
        for x in self.req.history :
            div = tags.div(**{"class" : "panel panel-default"})
            idiv = tags.div(**{"class" : "panel-heading"})

            char, total, spy, targ, tid = x
            tid = str(tid)

            if len(targ) and targ[0] == '/' :
               targ = targ[1:-1]

            a = tags.a(**{"class" : "panel-toggle", "style" : "display: inline", "data-toggle" : "collapse", "data-parent" : "#panelHistory" + tid, "href" : "#collapse" + tid})

            i = tags.i(**{"class" : "glyphicon glyphicon-arrow-down", "style" : "size: 50%"})
            i(" " + spy)
            a(i)
            idiv(char + " (" + str(int(float(total))) + "): ", a)
            cdiv = tags.div(**{"class" : "panel-body collapse", "id" : "collapse" + tid})
            icdiv = tags.div(**{"class" : "panel-inner"})
            icdiv(targ.replace("\"", "\\\"").replace("\'", "\\\""))#.replace("/", " /<br/>"))
            cdiv(idiv)
            div(idiv, cdiv)

            tag(div)

        return tag

class StaticNavElement(Element) :
    def __init__(self, req) :
        super(StaticNavElement, self).__init__() 
        self.req = req

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

class MobileAdvertElement(Element) :
    def __init__(self, req) :
        super(MobileAdvertElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/mobile_advert_template.html'))

    @renderer
    def mobile(self, request, tag) :
        tag.fillSlots(granted = _("To get a \"feel\" for how MICA works, you can use the DEMO account with the username 'demo' and password 'micademo'. This account will load pre-existing stories from the online demo account, but all changes you make will not be synchronized."))
        return tag

class ServerAdvertElement(Element) :
    def __init__(self, req) :
        super(ServerAdvertElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/server_advert_template.html'))

    @renderer
    def server(self, request, tag) :
        tag.fillSlots(granted = _("Accounts are granted on-request only."))
        return tag

class LinkAdvertElement(Element) :
    def __init__(self, req) :
        super(LinkAdvertElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/link_advert_template.html'))

    @renderer
    def link(self, request, tag) :
        tag.fillSlots(bitcoin = _("Please Donate To Bitcoin Address"))
        return tag

class FrontPageElement(Element) :
    def __init__(self, req) :
        super(FrontPageElement, self).__init__() 
        self.req = req

    loader = XMLFile(FilePath(cwd + 'serve/advertise_template.html'))

    @renderer
    def pages(self, request, tag) :
        if self.req.mobile :
            tag(XMLString("<div>" + self.req.deeper + "</div>").load())
        else :
            pages = [
                _("<b>MICA</b> is a <b>new way</b> to learn a language, like Chinese."),
                _("Instead of hiring folks to <b>slave over</b> databases of translations,"),
                _("Why can't we use the <b>existing content</b> that's already out there?"),
                _("Like <b>books</b>, blogs, new articles, and eventually <b>social media</b>."),
                _("MICA works by <b>analytics</b>: You read <b>existing</b> books or stories and it <b>tracks your brain</b>."),
                _("When you read a new story, it <b>hides the words</b> you already know."),
                _("It knows how to track <b>polymphones and tones</b> in a Character-based language."),
                _("MICA is not a translator. It makes you <b>learn by reading</b> in context."),
                _("Flashcards are stupid. <br/><b>Try MICA!</b> and learn a new language."),
            ]

            first = True

            for page in pages :
                if first :
                    first = False
                    div = tags.div(**{"class" : "item active", "style" : "text-align: center"})
                else :
                    div = tags.div(**{"class" : "item", "style" : "text-align: center"})

                div(tags.br(), tags.br(), tags.br(), tags.br())
                p = XMLString("<div>" + page + "</div>")
                div(tags.h1(style="width: 75%; margin: 0 auto;")(p.load()))
                div(tags.br(), tags.br(), tags.br(), tags.br())

                tag(div)

        return tag

    @renderer
    def mobilelinks(self, request, tag) :
        if not self.req.mobile :
            tag(LinkAdvertElement(self.req))
        else :
            tag("")
        return tag

    @renderer
    def frontend(self, request, tag) :
        if self.req.mobile :
            tag(MobileAdvertElement(self.req))
        else :
            tag(ServerAdvertElement(self.req))
            
        return tag

    @renderer
    def advertise(self, request, tag) :
        tag.fillSlots(learn =_("Learning a language should be just like reading a book"),
                      offline = _("MICA also works offline on mobile devices and automatically stays in sync with both iOS and Android"),
                      howitworks = _("Read about how it works on github.com"),
                      donation =_("Running the website on a cloud server is not free, so account signups are not open. If you'd like an account, please consider donating to make the server bigger."),
                      mailinglist = _("Join the mailing list"),
                      help = _("for additional help"),
                      connect =_("You need to connect, first"),
                      click =_("Click the little 'M' at the top"),
                      experimental = _("This is experimental language-learning software"))
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

            utag(StaticNavElement(self.req))
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
                     originallang = _("Original Language"),
                     yourlang = _("Your Language"),
                     removespaces = _("Remove Spaces?"),
                     mustbeencoded = _("NOTE: Story *must* be UTF-8 encoded"),
                     notimplemented = _("not implemented"),
                     multipage = _("multi-page"),
                     singlepage = _("single-page"),
                     whatkindfile = _("What kind of file is this?"),
                     selectfile = _("Select File"),
                     uploadfile = _("Upload File"),
                     uploadinstead = _("Or Upload a File Instead"),
                     uniquename = _("Unique Name"),
                     uploadtext = _("Upload Text"),
                     copypaste = _("Copy/Paste a Story"),
                     uploadstory = _("Upload Story"),
                     instant = _("Instant Translation"),
                     splitmerge = _("Split/Merge Words"),
                     create = _("Create"),
                     confirmpass = _("Confirm"),
                     password = _("Password"),
                     username = _("Username"),
                     newaccount = _("Create New Account"),
                     aboutsoftware = _("About this software"),
                     signin = _("Login"),
                     rememberme = _("Remember Me"),
                     address = _("Address")
                     )
       return tag

    @renderer
    def newaccountadmin(self, request, tag) :
        if self.req.session.value['connected'] and not self.req.pretend_disconnected :
            if self.req.user and 'admin' in self.req.user['roles'] :
                tag(tags.h5(" ", tags.input(type="checkbox", name="isadmin"), " " + _("Admin")))
        return tag

@defer.inlineCallbacks
def run_template(req, which, content = False) :
    try :
        if content :
            obj = which(req, content)
        else :
            obj = which(req)
    except Exception, e :
        merr("Failed to instantiate element: " + str(e) + " \n" + str(content))

    d = flattenString(None, obj)

    d.addErrback(mdebug)
    req.flat = yield d 

def load_template(req, which, content = False) :
    run_template(req, which, content)
    return req.flat

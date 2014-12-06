#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, tags, XMLString
from twisted.web._flatten import _flattenTree
from twisted.python.filepath import FilePath
from twisted.internet import defer
from cStringIO import StringIO
from common import *
from os import path as os_path
from re import compile as re_compile
from urllib2 import quote as urllib2_quote

softlangs = []
for l, readable in lang.iteritems() :
    locale = l.split("-")[0]
    if locale not in softlangs :
        softlangs.append((locale, readable))

if not mobile :
    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.compliance_fixes import facebook_compliance_fix, weibo_compliance_fix

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)

class StoryElement(Element) :
    def __init__(self, req, content) :
        super(StoryElement, self).__init__(XMLString("<html xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='story'>" + content + "</html>")) 
        self.req = req

    @renderer
    def story(self, request, tag) :
        tag.fillSlots(notreviewed = _("Not Reviewed"),
                      reading = _("Reading"),
                      # This appears in the side-panel when a story was just uploaded and has not yet been processed for reviewing yet.
                      untranslated = _("Untranslated"),
                      finished = _("Finished"),
                      stories = _("Stories"))
        return tag

class DeleteAccountElement(Element) :
    def __init__(self, req) :
        super(DeleteAccountElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/deleteaccount_template.html').path)

    @renderer
    def delete(self, request, tag) :
        tag.fillSlots(delete = _("Delete Account?"),
                      deleteconfirm = _("Yes, delete my account."),
                      suredelete = _("Are you sure you want to delete your account? This is IRREVERSIBLE."),
                      username = self.req.session.value["username"],
                      )
        return tag

class PasswordElement(Element) :
    def __init__(self, req) :
        super(PasswordElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/changepass_template.html').path)

    @renderer
    def password(self, request, tag) :
        tag.fillSlots(oldpassword =_("Old Password / Token"),
                      password = _("New Password / Token"),
                      confirm = _("Confirm Password / Token"),
                      change = _("Change Password / Token"),
                      reset = _("Reset Password / Token"),
                      )
        return tag

class HistoryElement(Element) :
    def __init__(self, req) :
        super(HistoryElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/history_template.html').path)

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
            cdiv(icdiv)
            div(idiv, cdiv)

            tag(div)

        return tag

class StaticNavElement(Element) :
    def __init__(self, req) :
        super(StaticNavElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/nav_template.html').path)

    @renderer
    def accountslots(self, request, tag) :
                      # Preferences is located inside the 'Account' drop-down on the top-most navigation panel. It presents all the various preferences that can be permanently stored on the user's account.
        tag.fillSlots(preferences = _("Preferences"),
                      # Disconnect means the same as "logout" or "sign out" and is located inside the 'Account' dropdown on the top-most navigation panel.
                      disconnect = _("Disconnect"),
                      # About is a traditional description of the software package itself that you might find in other help menus of other programs.
                      about = _("About"),
                      # Help is not the usual 'help' in a software program. Instead it takes you directly to a tutorial about exactly how the software works.
                      help = _("Help"),
                      # The software's privacy policy, such as what user information we keep and do not keep.
                      privacy = _("Privacy"),
                      switchclick = 'switchlist()' if ("connected" in self.req.session.value and self.req.session.value["connected"] and "current_story" in self.req.session.value) else "", 
                      )
        return tag

class EditHistoryElement(Element) :
    def __init__(self, req) :
        super(EditHistoryElement, self).__init__() 
        self.req = req
        self.loader = XMLString("<html xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='edit_history'/>")

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
                        # SPLIT is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
                        opstr = tags.div(style="color: blue; display: inline")(_("SPLIT") + "   ")
                    else :
                        # MERGE is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
                        opstr = tags.div(style="color: red; display: inline")(_("MERGE") + "   ")

                    iidiv(a, " (" + str(total) + "): " + char + ": ", opstr)

                    idiv(iidiv)

                    cdiv = tags.div(**{"class" : "panel-body collapse", "id" : "collapse" + tid})
                    icdiv = tags.div(**{"class" : "panel-inner"})
                    icdiv(result)
                    cdiv(icdiv)
                    idiv(cdiv)
                    div(idiv)
                tag(div)
            else :
                # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
                tag(tags.h4(_("No edit history available.")))
        else :
                # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
            tag(tags.h4(_("Edit history Disabled.")))

        return tag

class EditHeaderElement(Element) :
    def __init__(self, req) :
        super(EditHeaderElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/edit_header_template.html').path)

    @renderer
    def edit_header(self, request, tag) :
        tag.fillSlots(editname = _("Legend"),
                      processedits = self.req.process_edits,
                      splitmerge = _("Split/Merge Words"),
                      retrans = self.req.retrans,
                      previousmerge = _("These characters were previously merged into a word"),
                      previoussplit = _("This word was previously split into characters"),
                      # These recommendations are edit-mode recommendations offered by the software to bulk-process SPLIT/MERGE operations that have been discovered by analyzing the user's previous edit history.
                      tryrecco = _("Try Recommendations"),
                      # Re-translate the current page that the user is reading right now.
                      repage = _("Re-translate page"))
        return tag

class MobileAdvertElement(Element) :
    def __init__(self, req) :
        super(MobileAdvertElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/mobile_advert_template.html').path)

    @renderer
    def mobile(self, request, tag) :
        tag.fillSlots(feel = _("To get a \"feel\" for how MICA works, you can use the DEMO account with the username 'demo' and password 'micademo'. This account will load pre-existing stories from the online demo account, but all changes you make will not be synchronized."),
                      access = _("To login to this application with a regular account and begin syncing all of your devices with your web account, you must first request a free web account online @ http://readalien.com. After you have created an online account, you can then login with your email and password from your online account using any device that you like."))
        return tag

class ServerAdvertElement(Element) :
    def __init__(self, req) :
        super(ServerAdvertElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/server_advert_template.html').path)

    @renderer
    def server(self, request, tag) :
        tag.fillSlots(contact = _("For assistance, Contact:"))
        return tag

class LinkAdvertElement(Element) :
    def __init__(self, req) :
        super(LinkAdvertElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/link_advert_template.html').path)

    @renderer
    def link(self, request, tag) :
        tag.fillSlots(bitcoin = _("Please Donate To Bitcoin Address"))
        return tag

class MobileFrontElement(Element) :
    def __init__(self, req) :
        super(MobileFrontElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/frontpage_template.html').path)

    @renderer
    def mobilelinks(self, request, tag) :
        if self.req.front_ads :
            tag(tags.table()(LinkAdvertElement(self.req)))
        else :
            tag("")
        return tag

    @renderer
    def front(self, request, tag) :
        tag.fillSlots(learn =_("Learning a language should be just like reading a book"),
                      offline = _("MICA also works offline on mobile devices and automatically stays in sync with both iOS and Android"),
                      howitworks = _("Read about how it works"),
                      donation =_("Running the website on a cloud server is not free, so account signups are not open. If you'd like an account, please consider donating to make the server bigger."),
                      # Beginning of a sentence
                      mailinglist = _("Join the mailing list"))
        return tag

    @renderer
    def pages(self, request, tag) :
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

class ChatElement(Element) :
    def __init__(self, req) :
        super(ChatElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/chat_template.html').path)

    @renderer
    def chat(self, request, tag) :
        tag.fillSlots(temp_jabber_pw = self.req.session.value["temp_jabber_pw"],
                      spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                      loading = _("Loading Chat"),
                      xmpp = self.req.mpath + "/JSJaC-dec-2014/JSJaC.js",
                      username = urllib2_quote(self.req.session.value["username"]),
                     )
        return tag

class FrontPageElement(Element) :
    def __init__(self, req) :
        super(FrontPageElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/advertise_template.html').path)

    @renderer
    def frontend(self, request, tag) :
        if mobile :
            tag(MobileAdvertElement(self.req))
        else :
            tag(ServerAdvertElement(self.req))
            
        return tag

    @renderer
    def frontpage(self, request, tag) :
        if not mobile :
            tag(MobileFrontElement(self.req))
        else :
            tag("")
        return tag

    @renderer
    def advertise(self, request, tag) :
        # end of sentence.
        tag.fillSlots(help = _("for additional help"),
                      # i.e. signin or login
                      connect =_("You need to connect, first"),
                      click =_("Click the little 'M' at the top"),
                      experimental = _("This is experimental language-learning software"))
        return tag

class EditElement(Element) :
    def __init__(self, req) :
        super(EditElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/edit_template.html').path)

    @renderer
    def edit(self, request, tag) :
        tag(EditHeaderElement(self.req))
        tag(EditHistoryElement(self.req))
        return tag

class LegendElement(Element) :
    def __init__(self, req) :
        super(LegendElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/legend_template.html').path)

    @renderer
    def legend(self, request, tag) :
                     # 'Legend' is the same as you would see in any statistical graph or chart that displays data in a graphical format and identifies which series you are looking at in the graph
        tag.fillSlots(title = _("Legend"),
                      # This appears in the 'Review'-mode legend while reading a story: This means that MICA's translation of a particular word containing this color as identified by the legend is correct: Both the meaning of the translated word is correct and the tone is correct. If the original language of the story is not from a character-based Language, like Chinese, then 'tone' is irrelevant and can be ommitted.
                      legend1 = _("Correct for tone and meaning"),
                      # This appears in the 'Review'-mode legend while reading a story: Because the tone and meaning are correct, this word does not need to be reviewed.
                      legend1post = _("(No review necessary)"),
                      # This appears in the 'Review'-mode legend while reading a story: It indicates that a word of this color as identified by the legend has multiple meanings and needs to be reviewed. 
                      legend2 = _("Possibly wrong meaning"),
                      # This appears in the 'Review'-mode legend while reading a story: It indicates that while this word needs to be reviewed for its meaning, the tone is still accurate. 
                      legend2post = _("(but tone is correct)"),
                      # This appears in the 'Review'-mode legend while reading a story: It indicates that a word of this color as identified needs to be reviewed for both its tone.
                      legend3 = _("Possibly wrong tone"),
                      # This appears in the 'Review'-mode legend while reading a story: It indicates that a word of this color as identified needs to be reviewed for both its tone as well as its meaning.
                      legend3post = _("(as well as meaning)"),
                      # This appears in the 'Review'-mode legend while reading a story:  It indicates that a previously reviewed word was identified by (and auto-corrected by) the user's previous review history and may or may not need to be reviewed again.
                      legend4 = _("Definitely wrong previously"),
                      # This appears UNDER the Legend in Review mode. It itemizes a detailed history of the changes that were made for all words of this page in the story while in review mode.
                      history = _("Change History"),
                      processreviews = self.req.process_reviews,
                      tryrecco = _("Try Recommendations"),
                      # This is the title of a pop-up when the user click's "Try Recommendations" in Review mode to process several words in 'bulk' at one time
                      reviews = _("Bulk Review Words"),
                      reviewchange = _("Change"),
                      # This appears inside the pop-up when the user click's "Try recommendations" in Review mode, but there were no recommendations available.
                      norecommend = _("No review recommendations available."),
                 )
        return tag

class DynamicViewElement(Element) :
    def __init__(self, req) :
        super(DynamicViewElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/dynamic_view_template.html').path)

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

        tag.fillSlots(processsplits = splits, processmerges = merges, processsplitstitle = _("Split this word into multiple characters"), processmergestitle = _("Merge these characters into a single word"))
        return tag

class ReadingViewElement(Element) :
    def __init__(self, req) :
        super(ReadingViewElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/reading_view_template.html').path)

    @renderer
    def reading_view(self, request, tag) :
        tag.fillSlots(meaningclasstitle = _("show/hide translations"))
        return tag

class StaticViewElement(Element) :
    def __init__(self, req) :
        super(StaticViewElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/static_view_template.html').path)

    @renderer
    def static_view(self, request, tag) :
        tclasses = dict(text = "", images = "", both = "")

        for which, unused in tclasses.iteritems() :
            if "view_mode" in self.req.session.value :
                 if self.req.session.value["view_mode"] == which :
                     tclasses[which] += "active "

            tclasses[which] += "btn btn-default"

        tclasses["meaning"] = ""

        if "meaning_mode" in self.req.session.value :
            if self.req.session.value["meaning_mode"] == "true" :
                tclasses["meaning"] += "active "
            tclasses["meaning"] += "btn btn-default"
                
        if mobile :
            assert("password" in self.req.session.value)
            assert("username" in self.req.session.value)

            if "language" not in self.req.session.value :
                onclick = ""
                mwarn("Strang missing language key error.")
            else :
                onclick = "process_instant(" + ("true" if self.req.gp.already_romanized else "false") + ",'" + self.req.session.value["language"] + "', '" + self.req.source_language + "', '" + self.req.target_language + "', '" + urllib2_quote(self.req.session.value["username"]) + "', '" + urllib2_quote(self.req.session.value["password"]) + "')"
        else :
            onclick = "process_instant(" + ("true" if self.req.gp.already_romanized else "false") + ",'" + self.req.session.value["language"] + "', '" + self.req.source_language + "', '" + self.req.target_language + "', false, false)"

        tag.fillSlots(textclass = tclasses["text"],
                      imageclass = tclasses["images"],
                      bothclass = tclasses["both"],
                      processinstant = onclick,
                      meaningclass = tclasses["meaning"],
                      textclasstitle = _("show text only"),
                      bothclasstitle = _("side-by-side text and image"),
                      imageclasstitle = _("show image only"),
                      processinstanttitle = _("instant translation of one or more words"),
                      )

        return tag

class ViewElement(Element) :
    def __init__(self, req) :
        super(ViewElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/view_template.html').path)

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
                      # This appears while reading a story: An 'instant translation' occurs by first clicking on one of the words, the word is highlighted. Then by clicking a button in the inner icon-bar that has a square with an arrow inside, it will perform an instant translation of the selected words by checking both offline and online dictionaries and the pop-up a dialog with the result of the instant translation.
                      performingtranslation= _("Doing instant translation..."),
                      # 'Go' or 'Skip' ahead to a specific page in a book/story.
                      go = _("Go"),
                      # Skip ahead to a specific page in a book/story.
                      gotitle = _("Skip to page"))
        
        return tag

    @renderer
    def view(self, request, tag) :
        tag(StaticViewElement(self.req))
        if self.req.action == "read" or self.req.action == "home" :
            tag(ReadingViewElement(self.req))
        if self.req.action == "edit" :
            tag(DynamicViewElement(self.req))
        return tag

class HeadElement(Element):
    def __init__(self, req) :
        super(HeadElement, self).__init__() 
        self.req = req
        self.loader = XMLFile(FilePath(cwd + 'serve/head_template.html').path)

    @renderer
    def languages(self, request, tag) :
        tag(tags.option(value='', selected='selected')(_("None Selected")))
        for l, readable in supported.iteritems() :
            if l in processor_map and processor_map[l] :
                option = tags.option(value=l)
                tag(option(_(readable)))
        return tag

    @renderer
    def user_languages(self, request, tag) :
        for l, readable in softlangs :
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
                 # 'Review' is a mode in which the software operates and is the first of 4 main buttons on the top-most navigation panel
                 ("home" , ("/home", "home", _("Review"))), 
                 # 'Edit' is a mode in which the software operates and is the second of 4 main buttons on the top-most navigation panel
                 ("edit" , ("/edit", "pencil", _("Edit"))), 
                 # 'Read' is a mode in which the software operates and is the third of 4 main buttons on the top-most navigation panel
                 ("read" , ("/read", "book", _("Read"))),
                 # 'Chat' is a mode where users can practice chatting with each other live with the assistance of the software and their learning history.
                 ("chat" , ("/chat", "comment", _("Chat"))),
            ]

        for (key, value) in menu :
            (url, icon, display) = value 
            itag = tags.i(**{"class":'glyphicon glyphicon-' + icon})
            if navactive == key :
                if mobile :
                    atag = tags.a(href=url, onclick = "$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});")(itag, " ", display)
                else :
                    atag = tags.a(href=url)(itag, " ", display)
                itemtag = tags.li(**{"class":"active"})
                tag(itemtag(atag))
            else :
                if mobile :
                    atag = tags.a(href=url, onclick = "$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});")(itag, " ", display)
                else :
                    atag = tags.a(href=url)(itag, " ", display)
                tag(tags.li(atag))

        if not self.req.pretend_disconnected :
            itemtag = tags.li(**{"class" : "dropdown"})
            atag = tags.a(**{"class" : "dropdown-toggle", "data-toggle" : "dropdown", "href" : "#"})
            # Account is the last button on the top-most navigation panel and results in a drop-down that provides configuration options for the user's account. 
            atag(tags.i(**{"class" : "glyphicon glyphicon-user"}), " " + _("Account") + " ", tags.b(**{"class" : "caret"}))
            utag = tags.ul(**{"class" : "dropdown-menu"})

            if not mobile :
                ttag = tags.a(**{"data-toggle" : "modal", "href" : "#uploadModal", "data-backdrop" : "static", "data-keyboard" : "false"})
                # Upload a story to MICA, a button inside the 'Account' section of the top-most navigation panel
                ttag(tags.i(**{"class" : "glyphicon glyphicon-upload"}), " " + _("Upload New Story"))
                utag(tags.li(ttag))

                if not mobile and "isadmin" in self.req.session.value and self.req.session.value["isadmin"] :
                    ttag = tags.a(**{"data-toggle" : "modal", "href" : "#newAccountModal", "data-backdrop" : "static", "data-keyboard" : "false"})
                    # Make a new account, a button inside the 'Account' section of the top-most navigation panel
                    ttag(tags.i(**{"class" : "glyphicon glyphicon-plus-sign"}), " " + _("New Account"))
                    utag(tags.li(ttag))

            utag(StaticNavElement(self.req))
            tag(itemtag(atag, utag))
        tag(tags.li(tags.a()(tags.b()(self.req.session.value["username"]))))
        return tag

    @renderer
    def scriptpopover(self, request, tag) :
        popoveractivate = "$('#connectpop').popover('show');"
        return tag(popoveractivate if (not self.req.session.value["connected"] and not self.req.skip_show and not self.req.pretend_disconnected) else "")

    @renderer
    def scriptswitch(self, request, tag) :
         return tag("" if not self.req.session.value["connected"] else ("switchinstall(" + ("true" if ('list_mode' in self.req.session.value and self.req.session.value['list_mode']) else "false") + ");\n"))

    @renderer
    def cloudnav(self, request, tag) :
        row = tags.tr()

        if self.req.session.value['connected'] and not self.req.pretend_disconnected :
            atag =  tags.a(href='#', id='offnav', onclick='togglecanvas()')
        else :
            atag = tags.a(href='#', id='offnav', onclick='')

        if not self.req.session.value['connected'] :
            atag(tags.img(id = "connectpop", src=self.req.mpath + '/icon-120x120.png', width='25px'))
        else :
            atag(tags.img(src=self.req.mpath + '/icon-120x120.png', width='25px'))

        row(tags.td(atag))

        row(tags.td(style='width: 2px')())

        if mobile :
            row(tags.td()(tags.i(**{"class" : "glyphicon glyphicon-download"})))
            row(tags.td(style='width: 2px')())
            pull = self.req.db.pull_percent() if self.req.db else ""
            if pull == "100.0" :
                pull = "100"
            row(tags.td(style='width: 2px')())
            row(tags.td()(tags.span(**{"class" : "badge pull-right", "id" : "pullstat"})(pull)))
            row(tags.td(style='width: 2px')())
            row(tags.td()(tags.i(**{"class" : "glyphicon glyphicon-upload"})))
            row(tags.td(style='width: 2px')())
            push = self.req.db.push_percent() if self.req.db else ""
            if push == "100.0" :
                push = "100"
            row(tags.td(style='width: 2px')())
            row(tags.td()(tags.span(**{"class" : "badge pull-right", "id" : "pushstat"})(push)))
            row(tags.td(style='width: 2px')())

        if "connected" in self.req.session.value and self.req.session.value["connected"] :
            rowcell = tags.td()
            rowcell(tags.a(href=''))
            viewstat = self.req.view_percent
            if viewstat == "100.0" :
                viewstat = "100"
            rowcell(tags.span(**{"class" : "badge pull-right", "id" : "viewstat"})(viewstat))
            row(rowcell)
            row(tags.td(style='width: 2px')())

            if not mobile :
                row(tags.td()(tags.i(**{"class" : "glyphicon glyphicon-eye-open"})))

            row(tags.td(style='width: 10px')())
        else :
            row(tags.td(style='width: 10px; align: center')(" "))
            # The name of the software
            row(tags.td()(tags.b()(_("MICA Language Learning"))))

            if not mobile :
                row(tags.td(style='width: 10px; align: center')(" "))
                row(tags.td(style='width: 10px; align: center')("|"))
                row(tags.td(style='width: 10px')())
                row(tags.td()(tags.b()(_("Change Language"))))
                row(tags.td(style='width: 10px')())

                rowcell = tags.td(style="font-size: x-small")
                       
                first = True

                for l, readable in softlangs :
                    if not first :
                        rowcell(" | ")
                    else :
                        first = False

                    rowcell(tags.a(href='/switchlang?lang=' + l)(readable))

                row(rowcell)

        tag(row)

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

        if mobile :
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
    def thirdparty(self, request, tag) :
       if mobile or ("connected" in self.req.session.value and self.req.session.value["connected"]):
           tag("")
       else : 
           tag(tags.br(), tags.b()(_("Sign in with")), ": ", tags.br())

           tr = tags.tr()

           for name, creds in self.req.oauth.iteritems() :
               if name == "redirect" :
                   continue
               service = OAuth2Session(creds["client_id"], redirect_uri=self.req.oauth["redirect"] + name, scope = creds["scope"])

               if name == "facebook" :
                   service = facebook_compliance_fix(service)

               if name == "weibo" :
                   service = weibo_compliance_fix(service)

               authorization_url, state = service.authorization_url(creds["authorization_base_url"])

               servicetag = tags.a(onclick = "$('#loginModal').modal({backdrop: 'static', keyboard: false, show: true});", href = authorization_url)
               servicetag(tags.img(width='30px', src=self.req.mpath + "/" + creds["icon"], style='padding-left: 5px'))
               tr(tags.td(servicetag))

           tag(tags.table()(tr))

       return tag
    @renderer
    def allslots(self, request, tag) :

       tag.fillSlots(jquery = self.req.bootstrappath + "/js/jquery.js",
                     bootminjs = self.req.bootstrappath + "/js/bootstrap.min.js",
                     bootmincss = self.req.bootstrappath + "/css/bootstrap.min.css",
                     micacss = self.req.mpath + "/mica.css",
                     micajs = self.req.mpath + "/mica.js",
                     favicon = self.req.mpath + "/icon-120x120.png",
                     bootpagejs = self.req.bootstrappath + "/js/jquery.bootpag.min.js",
                     # Which language to learn, that is.
                     langtype = _("Which language"),
                     email = _("Email Address"),
                     # The next series of messages occur in a dialog used to upload a new story. Stories can be uploaded by copy-and-paste or by PDF, currently and the user can choose a number of languages.
                     userlang = _("Preferred Language"),
                     # Character-based languages do not have a lot of spaces, so we provide an option to remove them before translation and review.
                     removespaces = _("Remove Spaces?"),
                     mustbeencoded = _("NOTE: Story *must* be UTF-8 encoded"),
                     notimplemented = _("not implemented"),
                     # Source story consists of multiple pages, like a PDF
                     multipage = _("multi-page"),
                     # Story is just a blob of TXT, such as copy/paste.
                     singlepage = _("single-page"),
                     # i.e. PDF or TXT
                     whatkindfile = _("What kind of file is this?"),
                     selectfile = _("Select File"),
                     uploadfile = _("Upload File"),
                     uploadinstead = _("Or Upload a File Instead"),
                     choose = _("Choose one"),
                     # Unique name to identify this story in the system
                     uniquename = _("Unique Name"),
                     noneselected = _("None Selected"),
                     uploadtext = _("Upload Text"),
                     copypaste = _("Copy/Paste a Story"),
                     missing = _("* Please fill in required fields"),
                     uploadstory = _("Upload Story"),
                     instant = _("Instant Translation"),
                     # Create account button
                     create = _("Create"),
                     # confirm password
                     confirmpass = _("Confirm"),
                     password = _("Password / Token"),
                     username = _("Account"),
                     newaccount = _("Create New Account"),
                     # This is one of the 'Account' menu items that describes the author of the software.
                     aboutsoftware = _("About this software"),
                     signin = _("Login"),
                     # This appears on the front page when you login and indicates whether to remember your username the next time you logout/login.
                     rememberme = _("Remember Me"),
                     # This appears on the front page when you login. It is the HTTP address of the website.
                     address = _("Address"),
                     spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                     signing = _("Signing you in, Please wait"),
                     
                     loading = _("Loading story, Please wait"),
                     loadingwait = _("If you have re-installed or this is your first time logging in on this device and you have chosen to synchronize many stories at the same time, this can take a while, because we need to calculate some information to organize things on your device. Be patient."),
                     # Compacting can also be translated as "cleaning" database.
                     compacting = _("Compacting database, Please wait"),
                     # This appears as a pop-up when we are loading the text content of a story.
                     loadingtext = _("Loading Text"),
                     # This appears as a pop-up when we are image content of a PDF-based story.
                     loadingimage = _("Loading Image"),
                     # This appears when you first click on a story to be loaded
                     loadingstories = _("Loading Stories"),
                     # This appears at the  bottom of the page when you are loading a story and indicates that the analytical/statistical information is also being loaded
                     loadingstatistics = _("Loading Statistics"),
                     # This appears on a mobile device and indicates that the devices is not fully sychronized with the website.
                     notsynchronized = _("This account is not fully synchronized"),
                     # This appears on a mobile device when you attempt to perform an instant translation. If the wifi is disconnect, you will see this message.
                     onlineoffline = _("If you are offline, please go online for an instant translation."),
                     # This appears when you attempt to perform an instant translation without clicking on any words to translate.
                     notselected = _("You have not selected any words for instant translation!"),
                     # This appears as a popup when you are preparing to perform a split/merge request in Edit mode, but some of the words you have chosen have errors. 
                     seeabove = _("See above for problems with your edit requests."),
                     # just a generic 'Submit' whenever you need to make changes or click to go to another page to perform an action.
                     submit = _("Submit"),
                     # This reason appears when you have made errors in Edit mode to explain why the software cannot proceed with your edits.
                     reason = _("Reason"),
                     # Merge as in merge/split in edit mode.
                     merge = _("Merge"),
                     # This appears next to the words that have errors for which you were trying to merge or split.
                     invalid = _("INVALID"),
                     # Split as in merge/split in edit mode.
                     split = _("Split"),
                     # This appears to confirm whether or not you want to merge or split one or more words in Edit mode.
                     areyousure = _("Are you sure you want to perform these edits?"),
                     # Also a message in edit mode.
                     notconsecutive = _("The selected characters are not consecutive (including punctuation). You cannot merge them."),
                     # Also a message in edit mode.
                     atleasttwo = _("You need at least two character groups selected before you can merge them into a word!"),
                     # Also a message in edit mode.
                     onlyhasone = _("This word only has one character. It cannot be split!"),
                     # Also a message in edit mode.
                     cannotsplit = _("You cannot split more than one word at a time!"),
                     # This appears on the left-hand panel when a story is being actively translated.
                     translating = _("Translating"),
                     # This on the main page when a story is being actively translated.
                     storiestranslating = _("Stories in translation"),
                     # This appears after a story has just finished being translated to indicate that you can start using it.
                     donereload = _("Done! Please reload."),
                     # This appears during the translation of a story to indicate how many pages have been completed in the translation
                     working = _("Working"),
                     # This 'page' also appears during the translation of a story to indicate how many pages have been completed in the translation
                     page = _("Page"),
                     # These appear in the Account menu and toggle between "Stats Hidden" and "Stats Shown" so that the statistics of each page can appear or disappear
                     statshide = _("Stats Hidden"),
                     statsshown = _("Stats Shown"),
                     requesting = _("Requesting"),
                     started = _("Started (stop?)"),
                     stopping = _("Stopping"),
                     stopped = _("Stopped (start?)"),
                     )
       return tag

    @renderer
    def newaccountadmin(self, request, tag) :
        if self.req.session.value['connected'] and not self.req.pretend_disconnected :
            if not mobile and "isadmin" in self.req.session.value and self.req.session.value["isadmin"] :
                # Admin account, that is
                tag(tags.h5(" ", tags.input(type="checkbox", name="isadmin"), " " + _("Admin")))
        return tag

def run_template(req, which, content = False) :
    try :
        if content :
            obj = which(req, content)
        else :
            obj = which(req)
    except Exception, e :
        return str(e)
        merr("Failed to instantiate element: " + str(e) + " \n" + str(content))

    io = StringIO()

    try :
        state = _flattenTree(None, obj)
        while True:
            element = state.next()
            if type(element) is str:
                io.write(element)
            else :
                break
    except StopIteration:
        pass

    return io.getvalue() 

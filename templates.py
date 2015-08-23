#!/usr/bin/env python

from twisted.web.template import Element, renderer, XMLFile, tags, XMLString
from twisted.web._flatten import _flattenTree
from twisted.python.filepath import FilePath
from twisted.internet import defer
from cStringIO import StringIO
from common import *
from os import path as os_path
from re import compile as re_compile

import pyratemp

softlangs = []
for l, readable in lang.iteritems() :
    locale = l.split("-")[0]
    if locale not in softlangs :
        softlangs.append((locale, readable))

if not mobile :
    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.compliance_fixes import facebook_compliance_fix, weibo_compliance_fix

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)

class MessagesElement(Element) :
    def __init__(self, req) :
        super(MessagesElement, self).__init__() 
        self.req = req
        self.loader = XMLString("<div xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='messages'><div class='img-rounded jumbotron' style='padding: 10px; margin: 0 auto'><t:attr name='style'><t:slot name='error_visible'/></t:attr> " + req.messages + "</div></div>")

    @renderer
    def messages(self, request, tag) :
        tag.fillSlots(
                error_visible = "display: none" if self.req.messages == "" else "display: block" ,
            )
        return tag

class CommonElement(Element) :
    def __init__(self, req, template_name = False, conditionals = {}) :
        super(CommonElement, self).__init__() 
        self.req = req
        if not template_name :
            template_name = self.__class__.__name__.replace("Element", "").lower()
            template_name += "_template.html"

        conditionals["mobile"] = mobile
        conditionals["req"] = req

        zoom_level = 1.0

        if mobile :
            if "default_app_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_app_zoom"]
        else :
            if "default_web_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_web_zoom"]

        conditionals["zoom_level"] = zoom_level

        for attrs in ["front_ads", "list_mode", "history", "credentials", "action", "userdb", "memresult", "memallcount", "mempercent", "story"] :
            if hasattr(self.req, attrs) :
                conditionals[attrs] = getattr(self.req, attrs)

        fh = open(cwd + 'serve/' + template_name, 'r')
        f = fh.read()
        fh.close()
        pt = pyratemp.Template(f)
        self.loader = XMLString(pt(**conditionals))
        #self.loader = XMLFile(FilePath(cwd + 'serve/' + template_name).path)

    @renderer
    def languages(self, request, tag) :
        if "learnlanguage" in self.req.session.value :
            wanted = supported_map[self.req.session.value["learnlanguage"]] + "," + supported_map[self.req.session.value["language"]]
        else :
            wanted = False
        if wanted not in supported :
            tag(tags.option(value='', selected='selected')(_("None Selected")))

        for l, readable in supported.iteritems() :
            if l in processor_map and processor_map[l] :
                if l == wanted :
                    option = tags.option(value=l, selected='selected')
                else :
                    option = tags.option(value=l)
                tag(option(_(readable)))
        return tag

class ReviewElement(CommonElement) :
    @renderer
    def review(self, request, tag) :
        tag.fillSlots(
                     onlineoffline = self.req.onlineoffline,
                     # statistics in reading mode are disabled
                     statdisabled = _("Statistics Disabled"),
                     # 'Legend' is the same as you would see in any statistical graph or chart that displays data in a graphical format and identifies which series you are looking at in the graph
                     title = _("Legend"),
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
                     tryrecco = _("Try Recommendations"),
                     reviewchange = _("Change"),
                     # This appears inside the pop-up when the user click's "Try recommendations" in Review mode, but there were no recommendations available.
                     norecommend = _("No review recommendations available."),
                     nb_page = self.req.page,
                     repage = _("Re-translate page"),
                     )
        return tag

class ReadElement(CommonElement) :
    @renderer
    def read(self, request, tag) :
        tag.fillSlots(
                        # In 'Reading' mode, we record lots of statistics about the user's behavior, most importantly: which words they have memorized and which ones they have not. 'Memorized all stories' is a concise statement that show the user a sum total number of across all stories of the number of words they have memorized in all.
                        memallstories = _("Memorized all stories"),
                        # Same as previous, except the count only covers the page that the user is currently reading and does not include duplicate words
                        memunique = _("Unique memorized page"),
                        # A count of all the unique words on this page, not just the ones the user has memorized.
                        uniquepage = _("Unique words this page"),
                        # statistics in reading mode are disabled
                        statdisabled = _("Statistics Disabled"),
                        nowords = _("No words memorized. Get to work!"),
                     )
        return tag

class TranslationsElement(CommonElement) :
    @renderer
    def translationslots(self, request, tag) :
        tag.fillSlots(
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
                     startsync = _("Start Syncing"),
                     stopsync = _("Stop Syncing"),
                     requestfailed = _("Failed to issue request. We're sorry. Please report what you tried to do to the author. Thank you."),
                )
        return tag

class ModalsElement(CommonElement) :
    @renderer
    def user_languages(self, request, tag) :
        for l, readable in softlangs :
            option = tags.option(value=l)
            tag(option(_(readable)))
        return tag

    @renderer
    def modalslots(self, request, tag) :
        tag.fillSlots(
                     admin = _("Admin"),
                     # This is one of the 'Account' menu items that describes the author of the software.
                     aboutsoftware = _("About this software"),
                     createnewaccount = _("Create New Account"),
                     # Create account button
                     create = _("Create"),
                     uploadstory = _("Upload Story"),
                     missing = _("* Please fill in required fields"),
                     nocolons = _("* File/Story name cannot have colons ':' characters in it. Please fix."),
                     choose = _("Choose one"),
                     copypaste = _("Copy/Paste a Story"),
                     # Unique name to identify this story in the system
                     uniquename = _("Unique Name"),
                     # Which language to learn, that is.
                     langtype = _("Which language"),
                     uploadtext = _("Upload Text"),
                     uploadinstead = _("Or Upload a File Instead"),
                     selectfile = _("Select File"),
                     # i.e. PDF or TXT
                     whatkindfile = _("What kind of file is this?"),
                     noneselected = _("None Selected"),
                     # Source story consists of multiple pages, like a PDF
                     multipage = _("multi-page"),
                     # Story is just a blob of TXT, such as copy/paste.
                     singlepage = _("single-page"),
                     notimplemented = _("not implemented"),
                     uploadfile = _("Upload File"),
                     mustbeencoded = _("NOTE: Story *must* be UTF-8 encoded"),
                     spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                     # This appears on the front page when you login. It is the HTTP address of the website.
                     signing = _("Signing you in, Please wait"),
                     loading = _("Loading story, Please wait"),
                     loadingwait = _("If you have re-installed or this is your first time logging in on this device and you have chosen to synchronize many stories at the same time, this can take a while, because we need to calculate some information to organize things on your device. Be patient."),
                     # Compacting can also be translated as "cleaning" database.
                     compacting = _("Compacting database, Please wait"),
                     instant = _("Instant Translation"),
                     splitmerge = _("Split/Merge Words"),
                     deleteconfirm = _("Yes, delete my account."),
                     suredelete = _("Are you sure you want to delete your account? This is IRREVERSIBLE."),
                     username = self.req.session.value["username"],
                     delete = _("Delete Account?"),
                      # This is the title of a pop-up when the user click's "Try Recommendations" in Review mode to process several words in 'bulk' at one time
                      reviews = _("Bulk Review Words"),
                     )
        return tag

class ChatElement(CommonElement) :
    @renderer
    def chat(self, request, tag) :
        tag.fillSlots(
                      temp_jabber_pw = self.req.session.value["temp_jabber_pw"] if not mobile else self.req.session.value["password"],
                      spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                      # Indicates that the chat software is starting up... 
                      loading = _("Loading Chat"),
                      username = self.req.session.value["username"].replace("@", "%40"),
                      beep = self.req.mpath + "/beep.wav",
                      # Incoming chat messages
                      incoming = _("Your Chat Username is: ") + self.req.session.value["username"].replace("@", "%40") + "@" + self.req.main_server,
                      # Send a chat message
                      sendmsg = _("Send Message"),
                      # Destination of chat receiver
                      to = _("To"),
                      server = self.req.main_server,
                      domain = self.req.main_server,
                      sendbutton = _("Send"),
                      processinstanttitle = _("instant translation of one or more words"),
                      processinstant = processinstantclick(self.req, request, tag),
                      performingtranslation= _("Doing instant translation..."),
                      # In Chat mode, from what source language to what target language should translations occur.
                      chatlangtype = _("Learn (translate) from"),
                      # Notification from the online chat system that another user is logged in and has become available.
                      hasbecome = _("has become available"),
                      # Notification from the online chat system that another user has changed status, like 'away' or 'available'.
                      setpresence = _("has set their presence to"),
                      # Appears in Chat mode and allows user to disable IME input system for character-based languages.
                      phonetic = _("phonetic typing"),
                      # Use a traditional or simplified character IME system
                      traditional = _("Traditional"),
                      provideaddress = _("Please provide the address of someone to chat with."),
                      jabber_key = self.req.session.value["jabber_key"],
                      notauthorized = _("Disconnected: You have probably logged in from a different web-browser. To resume your chat please sign-out an then sign-in again. Thank you."),
                      chaterror = _("An error occured"),
                      secsleft = _("Seconds left to reconnect"),
                      refreshtitle = _("Refresh"),
                     )
        return tag

class FrontPageElement(CommonElement) :
    @renderer
    def switchlangs(self, request, tag) :
        first = True
        original_language = catalogs.language
        for l, readable in softlangs :
            if not first :
                tag(" | ")
            else :
                first = False

            self.req.mica.install_local_language(self.req, l)
            tag(tags.a(href='/switchlang?lang=' + l)(_(readable)))

        self.req.mica.install_local_language(self.req, original_language)
        return tag

    @renderer
    def thirdparty(self, request, tag) :
       for name, creds in self.req.oauth.iteritems() :
           if name == "redirect" :
               continue
           service = OAuth2Session(creds["client_id"], redirect_uri=self.req.oauth["redirect"] + name, scope = creds["scope"])

           if name == "facebook" :
               service = facebook_compliance_fix(service)

           if name == "weibo" :
               service = weibo_compliance_fix(service)

           authorization_url, state = service.authorization_url(creds["authorization_base_url"])

           servicetag = tags.a(onclick = "loading()", href = authorization_url, title=name, **{"data-ajax" : "false"})
           servicetag(tags.img(width='30px', src=self.req.mpath + "/" + creds["icon"], style='padding-left: 5px'))
           tag(tags.td(servicetag))

       return tag

    @renderer
    def head(self, request, tag) :
        return HTMLElement(self.req)

    @renderer
    def advertise(self, request, tag) :
        tag.fillSlots(learn =_("Learning a language should be just like reading a book"),
                      offline = _("MICA also works offline on mobile devices and automatically stays in sync with both iOS and Android"),
                      howitworks = _("Read about how it works"),
                      donation =_("Running the website on a cloud server is not free, so account signups are not open. If you'd like an account, please consider donating to make the server bigger."),
                      # Beginning of a sentence
                      mailinglist = _("Join the mailing list"),
                      # end of sentence.
                      help = _("for additional help"),
                      # i.e. signin or login
                      connect =_("You need to connect, first"),
                      experimental = _("This is experimental language-learning software"),
                      bitcoin = _("Please Donate To Bitcoin Address"),
                      feel = _("To get a \"feel\" for how MICA works, you can use the DEMO account with the username 'demo' and password 'micademo'. This account will load pre-existing stories from the online demo account, but all changes you make will not be synchronized."),
                      access = _("To login to this application with a regular account and begin syncing all of your devices with your web account, you must first request a free web account online @ http://readalien.com. After you have created an online account, you can then login with your email and password from your online account using any device that you like."),
                      contact = _("For assistance, Contact:"),
                      username = _("OR Use a local account") if not mobile else _("Account"),
                      address = _("Address"),
                      password = _("Password / Token"),
                      signin = _("Login"),
                      # This appears on the front page when you login and indicates whether to remember your username the next time you logout/login.
                      rememberme = _("Remember Me"),
                      softwarename = _("MICA Language Learning"),
                      changelang = _("Change Language"),
                      signinwith = _("Sign in with"),
                      headjs = self.req.mpath + "/head.js",
                      )
        return tag

    @renderer
    def error(self, request, tag) :
        return MessagesElement(self.req)

    @renderer
    def pages(self, request, tag) :
        pages = [
            _("<b>MICA</b> is a <b>new way</b> to learn a language."),
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

            div(tags.br(), tags.br(), tags.br())
            p = XMLString("<div>" + page + "</div>")
            div(tags.h1(style="margin: 0 auto; width: 70%")(p.load()))
            div(tags.br(), tags.br(), tags.br())

            tag(div)

        return tag


class EditElement(CommonElement) :
    @renderer
    def edit(self, request, tag) :
        tag.fillSlots(editname = _("Legend"),
                      processedits = self.req.process_edits,
                      nb_page = self.req.page,
                      uuid = self.req.uuid,
                      previousmerge = _("These characters were previously merged into a word"),
                      previoussplit = _("This word was previously split into characters"),
                      # These recommendations are edit-mode recommendations offered by the software to bulk-process SPLIT/MERGE operations that have been discovered by analyzing the user's previous edit history.
                      tryrecco = _("Try Recommendations"),
                      # Re-translate the current page that the user is reading right now.
                      repage = _("Re-translate page"),
                      # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
                      editdisabled = _("Edit history Disabled."),
                      # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
                      noedits = _("No edit history available."),
                      # MERGE is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
                      merge = _("MERGE"),
                      # SPLIT is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
                      split = _("SPLIT"),
                      
                     )
        return tag

def processinstantclick(req, request, tag) :
    if mobile :
        assert("password" in req.session.value)
        assert("username" in req.session.value)

        if "language" not in req.session.value :
            onclick = ""
            mwarn("Strange missing language key error.")
        else :
            onclick = "process_instant(" + ("true" if req.gp.already_romanized else "false") + ",'" + req.session.value["language"] + "', '" + req.source_language + "', '" + req.target_language + "', '" + myquote(req.session.value["username"]) + "', '" + myquote(req.session.value["password"]) + "')"
    else :
        onclick = "process_instant(" + ("true" if req.gp.already_romanized else "false") + ",'" + req.session.value["language"] + "', '" + req.source_language + "', '" + req.target_language + "', false, false)"

    return onclick

class ViewElement(CommonElement) :
    @renderer
    def topview(self, request, tag) :
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
        stats = ""

        if self.req.action in ["read"] :
            stats = tags.div(id='memolist')
        elif self.req.action == "edit" :
            stats = tags.div(id='editslist')
        elif self.req.action == "home" :
            stats = tags.div(id='history')

        uuid = 'bad_uuid'

        splits = "process_edits('"
        merges = "process_edits('"

        if "current_story" in self.req.session.value :
            uuid = self.req.session.value["current_story"]

        splits += uuid
        merges += uuid
        splits += "', 'split', false)"
        merges += "', 'merge', false)"

        tag.fillSlots(storyname = self.req.story_name.replace("_", " "),
                      spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                      stats = stats,
                      installpages = self.req.install_pages,
                      # This appears while reading a story: An 'instant translation' occurs by first clicking on one of the words, the word is highlighted. Then by clicking a button in the inner icon-bar that has a square with an arrow inside, it will perform an instant translation of the selected words by checking both offline and online dictionaries and the pop-up a dialog with the result of the instant translation.
                      performingtranslation= _("Doing instant translation..."),
                      # 'Go' or 'Skip' ahead to a specific page in a book/story.
                      go = _("Go"),
                      # Skip ahead to a specific page in a book/story.
                      gotitle = _("Skip to page"),
                      textclass = tclasses["text"],
                      imageclass = tclasses["images"],
                      bothclass = tclasses["both"],
                      processinstant = processinstantclick(self.req, request, tag),
                      meaningclass = tclasses["meaning"],
                      textclasstitle = _("show text only"),
                      bothclasstitle = _("side-by-side text and image"),
                      imageclasstitle = _("show image only"),
                      processinstanttitle = _("instant translation of one or more words"),
                      meaningclasstitle = _("show/hide translations"),
                      processsplits = splits, processmerges = merges, processsplitstitle = _("Split this word into multiple characters"), processmergestitle = _("Merge these characters into a single word"),
                      refreshtitle = _("Refresh"),
                      resultshow = 'display: block' if self.req.resultshow else 'display: none',
                      result = (self.req.resultshow + ".") if self.req.resultshow else '',
                      )
        
        return tag

class HelpElement(CommonElement):
    def __init__(self, req) :
        super(HelpElement, self).__init__(req, req.tutorial) 

    @renderer
    def head(self, request, tag) :
        return HTMLElement(self.req)

    @renderer
    def help(self, request, tag) :
        return tag

class PrivacyElement(CommonElement):
    @renderer
    def head(self, request, tag) :
        return HTMLElement(self.req)

    @renderer
    def privacy(self, request, tag) :
        return tag

class DatabasesElement(CommonElement):
    @renderer
    def databaseslots(self, request, tag) :
        tag.fillSlots(
                        readable = _(self.readable),
                        remove = "1" if self.remove else "0", 
                        tofrom = self.pair,
                        dname = self.pair.replace("-", ""),
                        state = self.state,
                        )
        return tag

class AccountElement(CommonElement):
    @renderer
    def dicts(self, request, tag) :
        if mobile :
            tag(_("Dictionaries") + "?")
        else :
            # This allows the user to indicate on the website whether or not their mobile devices should synchronize a particular dictionary to their device.
            tag(_("Send Dictionaries to your devices?"))
        return tag

    def common_lang(self, tag, key) :
        for l, readable in softlangs :
            attrs = {"value" : l}
            if l == self.req.user[key] :
                attrs["selected"] = "selected"
            tag(tags.option(**attrs)(_(readable)))
        return tag

    @renderer
    def languages(self, request, tag) :
        return self.common_lang(tag, 'language')

    @renderer
    def learnlanguages(self, request, tag) :
        return self.common_lang(tag, 'learnlanguage')

    @renderer
    def databases(self, request, tag) :
        for pair, readable in self.req.supported.iteritems() :
            e = DatabasesElement(self.req)
            e.pair = pair
            e.readable = readable
            downloaded = False 
            if "filters" in self.req.user and pair in self.req.user["filters"]["files"] :
                downloaded = True

            e.remove = False
            if not downloaded :
                # The next few messages appear on mobile devices and allow the user to control the synchronization status
                # of the story they want to use. For example, if a story (or a dictionary) is on the website,
                # but not yet synchronized with the device, we show a series of messages as the user indicates
                # which ones to download/synchronize and which ones not to.
                e.state = _("Download")
            else :
                all_found = True

                lgp = self.req.processors[pair]
                for f in lgp.get_dictionaries() :
                    if not os_path.isfile(self.req.scratch + f) :
                        all_found = False
                        break

                e.remove = True
                if all_found :
                    e.state = _("Stop downloading")
                else :
                    e.state = _("Downloading") + "..."

            tag(e)
        return tag

    @renderer
    def accountslots(self, request, tag) :
        tag.fillSlots(
                        account = _("Account"),
                        username = self.req.session.value["username"],
                        offline = _("Offline dictionaries are required for using 'Edit' mode of some character-based languages and for re-translating individual pages in Review mode. Instant translations require internet access, so you can skip these downloads if your stories have already been edited/reviewed and you are mostly using 'Reading' mode. Each dictionary is somewhere between 30 to 50 MB each"),
                        # the zoom level or characters-per-line limit
                        changeview = _("Change Viewing configuration"),
                        charperline = _("Characters per line"),
                        perline = self.req.chars_per_line,
                        change = _("Change"),
                        zoom = _("Default zoom level"),
                        defaultzoom = self.req.default_zoom,
                        zoomchange = _("Change"),
                        language =_("Language"),
                        changelang = _("Change Language"),
                        learninglanguage = _("Learning Language"),
                        changelearnlang = _("Change Learning Language"),
                        compact = _("Compact databases"),
                        changepass = _("Change Password"),
                        changeemail = _("Email Address"),
                        email = self.req.user["email"] if "email" in self.req.user else _("Please Provide"),
                        emailchange = _("Please change your email address on the website. Will support mobile in a future version"),
                        changemail = _("Change Email"),
                        deleteaccount = _("Delete Account?"),
                        mobiledelete = _("Please delete your account on the website and then uninstall the application. Will support mobile in a future version."),
                        oldpassword =_("Old Password / Token"),
                        password = _("New Password / Token"),
                        confirm = _("Confirm Password / Token"),
                        passchange = _("Change Password / Token"),
                        reset = _("Reset Password / Token"),
                        passonline = _("Please change your password on the website. Will support mobile in a future version."),
                        accounts = _("Accounts"),
                        resultshow = 'display: block; padding: 10px' if self.req.resultshow else 'display: none',
                        result = (self.req.resultshow + ".") if self.req.resultshow else '',
                        delete = _("Delete"),

                     )
        return tag

class HTMLElement(CommonElement):
    @renderer
    def html(self, request, tag) :
        tag.fillSlots(
                     jqmcss = self.req.mpath + "/jquery.mobile.structure-1.4.5.min.css",
                     jqmtheme = self.req.mpath + "/jqmica/jqmica.min.css",
                     jqmthemeicons = self.req.mpath + "/jqmica/jquery.mobile.icons.min.css",
                     bootmincss = self.req.bootstrappath + "/css/bootstrap.min.css",
                     micacss = self.req.mpath + "/mica.css",
                     favicon = self.req.mpath + "/icon-120x120.png",
                     imecss = self.req.mpath + "/chinese-ime/ime.css",
                     jquery = self.req.mpath + "/jquery-1.11.3.min.js",
                     jquery_full = self.req.mpath + "/jquery-1.11.3.js",
                     micajs = self.req.mpath + "/mica.js",
                     bootminjs = self.req.bootstrappath + "/js/bootstrap.min.js",
                     jqmjs = self.req.mpath + "/jquery.mobile-1.4.5.min.js",
                     xmpp = self.req.mpath + "/JSJaC-dec-2014/JSJaC.js",
                     ime = self.req.mpath + "/chinese-ime/jQuery.chineseIME.js",
                     bootpagejs = self.req.bootstrappath + "/js/jquery.bootpag.min.js",
                     caret = self.req.mpath + "/chinese-ime/caret.js",
                    )

        return tag

class HeadElement(CommonElement):
    @renderer
    def messages(self, request, tag) :
        return MessagesElement(self.req)

    @renderer
    def modals(self, request, tag) :
        return ModalsElement(self.req)

    @renderer
    def translations(self, request, tag) :
        return TranslationsElement(self.req)

    @renderer
    def head(self, request, tag) :
        return HTMLElement(self.req)

    @renderer
    def allslots(self, request, tag) :
        pull = self.req.db.pull_percent() if self.req.db else ""
        if pull == "100.0" :
            pull = "100"
        push = self.req.db.push_percent() if self.req.db else ""
        if push == "100.0" :
            push = "100"
        viewstat = self.req.view_percent
        if viewstat == "100.0" :
            viewstat = "100"

        tag.fillSlots(
                     notreviewed = _("Not Reviewed"),
                     chatting = _("Chat History"),
                     reading = _("Reading"),
                     # This appears in the side-panel when a story was just uploaded and has not yet been processed for reviewing yet.
                     untranslated = _("Untranslated"),
                     finished = _("Finished"),
                     stories = _("Stories"),
                     email = _("Email Address"),
                     # The next series of messages occur in a dialog used to upload a new story. Stories can be uploaded by copy-and-paste or by PDF, currently and the user can choose a number of languages.
                     userlang = _("Preferred Language"),
                     # Character-based languages do not have a lot of spaces, so we provide an option to remove them before translation and review.
                     removespaces = _("Remove Spaces?"),
                     username = _("Account"),
                     accountusername = self.req.session.value["username"],
                     account = _("Username"),
                     password = _("Password / Token"),
                     # confirm password
                     confirmpass = _("Confirm"),
                     # 'Read' is a mode in which the software operates and is the third of 4 main buttons on the top-most navigation panel
                     readmode = _("Read"),
                     # This appears in the left-hand pop-out side panel and allows the user to throw away (i.e. Forget) the currently processed version of a story. Afterwards, the user can subsequently throw away the story completely or re-translate it. 
                     forget = _("Forget"),
                    # This appears in the left-hand pop-out side panel and allows the user to change their mind and indicate that they are indeed not finished reading the story. This will move the story back into the 'Reading' section. 
                     notfinished = _("Not finished"),
                     # This appears in the left-hand pop-out side panel and allows the user to indicate that they have finished with a story and do not want to see it at the top of the list anymore. This will move the story back into the 'Finished' section. 
                     finishedoption = _("Finished reading"),
                     # This appears in the left-hand pop-out side panel and allows the user to change their mind and indicate that they are not finished reviewing a story. This will move the story back into the 'Reviewing' section. 
                     notreviewedoption = _("Review not complete"),
                     # This appears in the left-hand pop-out side panel and allows the user to indicate that they have finished reviewing a story for accuracy. This will move the story into the 'Reading' section. 
                     reviewed = _("Review Complete"),
                     # The romanization is the processed (translated), romanized version of the original story text that was provided by the user for language learning.  
                     romanized = _("Download Romanization"),
                     # 'original' refers to the original text of the story that the user provided for language learning.
                     original = _("Download Original"),
                     # This appears in the left-hand pop-out side panel and allows the user to remove a story from the system completely.
                     delete = _("Delete"),
                     # This appears in the left-hand pop-out side panel and allows the user to begin conversion of a newly uploaded story into MICA format for learning. 
                     translate = _("Translate"),
                     # 'Review' is a mode in which the software operates and is the first of 4 main buttons on the top-most navigation panel
                     reviewmode = _("Review"),
                     # 'Edit' is a mode in which the software operates and is the second of 4 main buttons on the top-most navigation panel
                     editmode = _("Edit"),
                     mpath = self.req.mpath + '/icon-120x120.png',
                     pull = pull,
                     push = push,
                     viewstat = viewstat,
                     # Preferences is located inside the 'Account' drop-down on the top-most navigation panel. It presents all the various preferences that can be permanently stored on the user's account.
                     preferences = _("Preferences"),
                     # Disconnect means the same as "logout" or "sign out" and is located inside the 'Account' dropdown on the top-most navigation panel.
                     disconnect = _("Disconnect"),
                     # About is a traditional description of the software package itself that you might find in other help menus of other programs.
                     about = _("About"),
                     # Help is not the usual 'help' in a software program. Instead it takes you directly to a tutorial about exactly how the software works.
                     help = _("Help"),
                     # The software's privacy policy, such as what user information we keep and do not keep.
                     privacy = _("Privacy"),
                     switchclick = 'switchlist()' if ("connected" in self.req.session.value and self.req.session.value["connected"] and "current_story" in self.req.session.value) else "", 
                     uploadstory = _("New Story"),
                     # Make a new account, a button inside the 'Account' section of the top-most navigation panel
                     newaccount = _("New Account"),
                     chat = _("Chat"),
                     learn = _("Learn"),
                     instant = _("Instant Translation"),
                     performingtranslation= _("Doing instant translation..."),
                     spinner = tags.img(src=self.req.mpath + '/spinner.gif', width='15px'),
                     )
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

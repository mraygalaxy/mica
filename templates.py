# coding: utf-8

from twisted.web.template import Element, renderer, tags, XMLString
from twisted.web._flatten import _flattenTree
from cStringIO import StringIO
from common import *
from os import path as os_path
from re import compile as re_compile
from traceback import format_exc, print_stack

import pyratemp

softlangs = []
for l, readable in lang.iteritems() :
    locale = l.split("-")[0]
    if locale not in softlangs :
        softlangs.append((locale, readable))

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)

def unicheck(var) :
    if isinstance(var, unicode) :
        return var.encode("utf-8")
    return var

class MessagesElement(Element) :
    def __init__(self, req) :
        super(MessagesElement, self).__init__() 
        self.req = req
        if req.messages.count("Exception") :
            req.messages = req.messages.replace("<", "&#60;").replace(">", "&#62;")
        xstring = "<div xmlns:t='http://twistedmatrix.com/ns/twisted.web.template/0.1' t:render='messages'><div class='img-rounded jumbotron' style='padding: 10px; margin: 0 auto'><t:attr name='style'><t:slot name='error_visible'/></t:attr> " + req.messages + "</div></div>"
        #mverbose("Rendering: " + xstring)
        self.loader = XMLString(unicheck(xstring))

    @renderer
    def messages(self, request, tag) :
        tag.fillSlots(
                error_visible = "display: none" if self.req.messages == "" else "display: block" ,
            )
        return tag

class CommonElement(Element) :
    def __init__(self, req, template_name = False, conditionals = {}, frontpage = False) :
        super(CommonElement, self).__init__() 
        self.req = req
        if not template_name :
            template_name = self.__class__.__name__.replace("Element", "").lower()
            template_name += "_template.html"

        conditionals["mobile"] = mobile
        conditionals["req"] = req
        conditionals["frontpage"] = frontpage

        zoom_level = 1.0

        if mobile :
            if "default_app_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_app_zoom"]
        else :
            if "default_web_zoom" in self.req.session.value :
                zoom_level = self.req.session.value["default_web_zoom"]

        conditionals["zoom_level"] = zoom_level

        for attrs in ["gp", "front_ads", "list_mode", "history", "credentials", "action", "userdb", "memresult", "memallcount", "mempercent", "story"] :
            if hasattr(self.req, attrs) :
                conditionals[attrs] = getattr(self.req, attrs)

        if hasattr(self.req, "template_dict") :
            conditionals.update(self.req.template_dict)

        fh = open(cwd + 'serve/' + template_name, 'r')
        f = fh.read()
        fh.close()
        pt = pyratemp.Template(f)
        #mverbose("Rendered: " + pt(**conditionals))
        self.loader = XMLString(unicheck(pt(**conditionals)))

    def pullpush(self) :
        pull = self.req.db.pull_percent() if self.req.db else "0"
        if pull == "100.0" :
            pull = "100"
        push = self.req.db.push_percent() if self.req.db else "0"
        if push == "100.0" :
            push = "100"

        return pull, push

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
            tag(tags.a(**{"style" : "cursor: pointer", "onclick" : "window.location.href='" + "/switchlang?lang=" + l + "'", "data-role" : "none"})(_(readable)))

        self.req.mica.install_local_language(self.req, original_language)
        return tag

    @renderer
    def thirdparty(self, request, tag) :
        for name, creds in self.req.oauth.iteritems() :
            if name == "redirect" :
                continue

            servicetag = tags.a(**{ "onclick" : "loading()", "href" : self.req.session.value["states_urls"]["urls"][name], "title" : name, "data-ajax" : "false", "id" : "oauth_" + name})
            servicetag(tags.img(width='50px', src=self.req.mpath + "/" + creds["icon"], style='padding-left: 5px'))

            tag(tags.td(servicetag))

        return tag


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
                     # This appears in the 'Review'-mode legend while reading a story: This means that MLL's translation of a particular word containing this color as identified by the legend is correct: Both the meaning of the translated word is correct and the tone is correct. If the original language of the story is not from a character-based Language, like Chinese, then 'tone' is irrelevant and can be ommitted.
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
                     # This is a button that performs some modifications to a story automatically based on a series of recommendations.
                     tryrecco = _("Try Recommendations"),
                     # Change/submit the value of a field on the website.
                     reviewchange = _("Change"),
                     # This appears inside the pop-up when the user click's "Try recommendations" in Review mode, but there were no recommendations available.
                     norecommend = _("No review recommendations available."),
                     nb_page = self.req.page,
                     # This is a button that allows a particular page of a story to be re-translated.
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
                        # This is informing the user that there is no data in the system and to encourage them to begin reading this particular story.
                        nowords = _("No words memorized. Get to work!"),
                     )
        return tag

class RowElement(CommonElement) :
    @renderer
    def row(self, request, tag) :
        tag.fillSlots(
            spinner = tags.img(src=self.req.mpath + '/'+ spinner, width='15px'),
            transclass = 'transroman' if self.req.gp.already_romanized else 'trans',
            )
        return tag

class Row1Element(RowElement) : pass
class Row2Element(RowElement) : pass
class Row3Element(RowElement) : pass

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
                     # This is a status message indicating that a story has been 'requested' for download to the mobile device.
                     requesting = _("Requesting"),
                     # This is a status message indicating that a story has been 'started' for download to the mobile device.
                     started = _("Started (stop?)"),
                     # This is a status message indicating that a story has begun, but not yet fully 'stopped' for download to the mobile device.
                     stopping = _("Stopping"),
                     # This is a status message indicating that a story has been 'stopped' for download to the mobile device.
                     stopped = _("Stopped (start?)"),
                     # This is a status message indicating whether or not to start downloading a story to the mobile device.
                     startsync = _("Start Syncing"),
                     # This is a status message indicating whether or not to stop downloading a story to the mobile device.
                     stopsync = _("Stop Syncing"),
                     # This is a standard error message that a request on the website failed. 
                     requestfailed = _("Failed to issue request. We're sorry. Please report what you tried to do to the author. Thank you."),
                     favicon = self.req.mpath + "/icon-120x120.png",
                     # 'me' refers to the yourself inside of a chat window. 
                     me = _("me"),
                     # This message appears in a chat window.
                     largemessage = _("A very large message has been received. This might be due to an attack meant to degrade the chat performance. Output has been shortened."),
                     # name of the company.
                     alltitle = _("Read Alien: Meta Language Learning"),
                     # name of the company
                     companyname = _("Read Alien"),
                     # This appears as a push notification on a mobile device when a notification arrives. 
                     notification = _("ReadAlien Message from"),
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
                     # Create a new account button
                     create = _("Create"),
                     # Upload a new story button
                     uploadstory = _("Upload Story"),
                     # When uploading a story, this appears when the user forgot to do something
                     missing = _("* Please fill in required fields"),
                     # When uploading a story, you can't have colons in the file name
                     nocolons = _("* File/Story name cannot have colons ':' characters in it. Please fix."),
                     # Instruction to pick from a list of options
                     choose = _("Choose one"),
                     # Instruction to select from the option to copy/paste a story or upload a file
                     copypaste = _("Copy/Paste a Story"),
                     # Unique name to identify this story in the system
                     uniquename = _("Unique Name"),
                     # Which language to learn, that is.
                     langtype = _("Which language"),
                     # Button to upload a new block of text
                     uploadtext = _("Upload Text"),
                     # Button to upload a file
                     uploadinstead = _("Or Upload a File Instead"),
                     # Choose a file from your computer to upload
                     selectfile = _("Select File"),
                     # i.e. PDF or TXT
                     whatkindfile = _("What kind of file is this?"),
                     # No file was selected for upload
                     noneselected = _("None Selected"),
                     # Source story consists of multiple pages, like a PDF
                     multipage = _("multi-page"),
                     # Story is just a blob of TXT, such as copy/paste.
                     singlepage = _("single-page"),
                     # This particular type of file is not supported/implemented
                     notimplemented = _("not implemented"),
                     uploadfile = _("Upload File"),
                     # UTF-8 is a type of file format that.
                     mustbeencoded = _("NOTE: Story *must* be UTF-8 encoded"),
                     spinner = tags.img(src=self.req.mpath + '/'+ spinner, width='15px'),
                     # This appears on the front page when you login. It is the HTTP address of the website.
                     signing = _("Signing you in, Please wait"),
                     # This appears when you open a story for reading
                     loading = _("Loading story, Please wait"),
                     loadingwait = _("If you have re-installed or this is your first time logging in on this device and you have chosen to synchronize many stories at the same time, this can take a while, because we need to calculate some information to organize things on your device. Be patient."),
                     # Compacting can also be translated as "cleaning" database.
                     compacting = _("Compacting database, Please wait"),
                     # An instant translation message appears when choosing to translate an individual word
                     instant = _("Instant Translation"),
                     # This is used for Chinese characters when grouping or separating characters together into a single word
                     splitmerge = _("Split/Merge Words"),
                     # Button that confirms that the user wants to perform an action.
                     deleteconfirm = _("Yes, do it."),
                     suredelete = _("Are you sure? This is IRREVERSIBLE."),
                     username = self.req.session.value["username"],
                     chatusername = self.req.session.value["username"].replace("@", "%40"),
                     # Do you want to delete your account?
                     delete = _("Delete Account?"),
                     # This is the title of a pop-up when the user click's "Try Recommendations" in Review mode to process several words in 'bulk' at one time
                     reviews = _("Bulk Review Words"),
                     # This is a button that displays a set of instructions for teachers to use the mobile device.
                     )
        return tag

class ChatElement(CommonElement) :
    @renderer
    def chat(self, request, tag) :
        tag.fillSlots(
                      temp_jabber_pw = self.req.session.value["temp_jabber_pw"] if not mobile else self.req.session.value["password"],
                      spinner = tags.img(src=self.req.mpath + '/' + spinner, width='15px'),
                      # Indicates that the chat software is starting up... 
                      loading = _("Loading Chat"),
                      username = self.req.session.value["username"].replace("@", "%40"),
                      beep = self.req.mpath + "/beep.wav",
                      # Incoming chat messages
                      incoming = _("Your Chat Username is: ") + self.req.session.value["username"].replace("@", "%40") + "@" + self.req.main_server,
                      # Send a chat message
                      sendmsg = _("Send"),
                      # Buddy list
                      buddies = _("Buddies"),
                      # Destination of chat receiver
                      to = _("To"),
                      server = self.req.main_server,
                      domain = self.req.main_server,
                      # Send an instant message
                      sendbutton = _("Send"),
                      # This appears as a title for the results of an instant translation of one or more words
                      processinstanttitle = _("instant translation of one or more words"),
                      processinstant = processinstantclick(self.req, request, tag),
                      # This appears when an instant translation is in progress
                      performingtranslation= _("Doing instant translation..."),
                      # This appears when we do not have internet connectivity
                      chatoffline = _("Internet access is unavailable. Chat offline."),
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
                      # We need the user to gives a username of someone to chat with
                      provideaddress = _("Please provide the address of someone to chat with."),
                      jabber_key = self.req.session.value["jabber_key"],
                      notauthorized = _("Disconnected: You have probably logged in from a different web-browser. To resume your chat please sign-out an then sign-in again. Thank you."),
                      # A general error message
                      chaterror = _("An error occured"),
                      # This message appears as part of a count-down message indicating how many seconds are left before the system re-connects to the chat
                      secsleft = _("Seconds left to reconnect"),
                      # This is a button for the user to restart the current webpage
                      refreshtitle = _("Refresh"),
                     )
        return tag

class FrontPageElement(CommonElement) :
    @renderer
    def head(self, request, tag) :
        return HTMLElement(self.req, frontpage = True)

    @renderer
    def login(self, request, tag) :
        return LoginElement(self.req)
        
    @renderer
    def advertise(self, request, tag) :
        pull, push = self.pullpush()
                      # front-page website message
        tag.fillSlots(learn =_("Democratize Languages: Learning a language should be just like reading a book"),
                      crewjs = self.req.mpath + "/crewjs/crew.min.js",
                      # front-page website message
                      offline = _("Read Alien also works offline on mobile devices and automatically stays in sync with both iOS and Android"),
                      # front-page website message
                      howitworks = _("Read about how it works"),
                      # The software's privacy policy, such as what user information we keep and do not keep.
                      privacy = _("Privacy"),
                      # Beginning of a sentence
                      mailinglist = _("Join the mailing list"),
                      # end of sentence.
                      help = _("for additional help"),
                      # i.e. signin or login
                      connect =_("You need to connect, first"),
                      experimental = _("This is experimental language-learning software"),
                      bitcoin = _("Please Donate To Bitcoin Address"),
                      feel = _("To get a \"feel\" for how Read Alien works, you can use the DEMO account with the username 'demo' and password 'micademo'. This account will load pre-existing stories from the online demo account, but all changes you make will not be synchronized."),
                      access = _("To login to this application with a regular account and begin syncing all of your devices with your web account, you must first request a free web account online @ http://readalien.com. After you have created an online account, you can then login with your email and password from your online account using any device that you like."),
                      # direct the user to contact information for the website
                      contact = _("For assistance, Contact:"),
                      # A 'local' account is an account that does not use a social network, like facebook or google.
                      username = _("OR Use a local account") if not mobile else _("Account"),
                      # An address is a website address for the location of the database.
                      address = _("Address"),
                      # Just a password
                      password = _("Password / Token"),
                      # Login to the website 
                      signin = _("Login"),
                      # This appears on the front page when you login and indicates whether to remember your username the next time you logout/login.
                      rememberme = _("Remember Me"),
                      # name of the company
                      softwarename = _("Read Alien Learning"),
                      # Switch the website to a different language
                      changelang = _("Change Language"),
                      # 'Sign in with' a specific social network, like facebook or google
                      signinwith = _("Sign in with"),
                      headjs = self.req.mpath + "/head.js",
                      pull = pull,
                      push = push,
                      # Landing page navigation link #1: Scroll back to the beginning
                      home = _("Home"),
                      # An example story / book in Spanish
                      spanishexample = _("Spanish Example"),
                      # An example story / book in Chinese 
                      chineseexample = _("Chinese Example"),
                      # This is a technology phrase: It means that a website is designed with a priority to run a mobile device and a priority to be able to run offline without the need for an internet connection.
                      offlinemobile = _("Offline-first. Mobile-first."),
                      # Chat / Instant Messaging
                      chat = _("Chat"),
                      # Login to the website
                      login = _("Login"),
                      # Features of this software
                      features = _("Features"),
                      # Mobile device
                      mobile = _("Mobile"),
                      # Open source software
                      opensource = _("Open Source"),
                      # Front-page message
                      democratize = _("Democratize Languages"),
                      # Front-page message
                      learningshould = _("Learning a language should be just like reading a book"),
                      # "driven" means that the software is powered by open-source software
                      driven = _("Driven by open-source"),
                      # Front-page message: learn spanish and chinese for free
                      spanishchineseforfree = _("Spanish and Chinese for Free"),
                      # Learn a language by uploading your own foreign literature
                      youprovide= _("Learn foreign literature that you provide"),
                      # Learn the way you want to
                      yourterms = _("On your terms"),
                      # This software uses data to track your language progress
                      datadriven = _("Data-driven software tracks your language"),
                      # This means that you don't have to work that hard 
                      haveto = _("So you don't have to"),
                      # Reduce the fear of communication in a foreign language by chatting with native speakers 
                      native = _("Chat like a native. Reduce the fear."),
                      # We use data to assist your language experience
                      realtime = _("Data drives your language in real-time."),
                      # Guess what words you know and don't know. Learn the language for a long time.
                      guess = _("Guess all day. Learn all night."),
                      # Languages that have multiple tons (like chinese) are hard to learn.
                      tonal = _("Tonal languages are hard."),
                      # You do not need to use rote-memorization (repeat, repeat, repeat) to learn the language
                      rote = _("We bring an end to rote-memorization."),
                      # We show you your vocabulary at the same time you are typing in the chat window
                      overlay = _("Overlay verb conjugations with an IME-style keyboard to real-time assist the person you're talking to. Data from the literature that you read feeds directly into a context-based learning experience."),
                      # Polyphomes refer to multiple tones in a language, like chinese. grouping merging refers to putting two characters together to form a whole word.
                      polyphomes = _("We support polyphomes, character grouping/merging, and complex parsing of character-based languages."),
                      # Conjugate refers to romanized languages, like Spanish, that have different spellings of a verb for different tenses.
                      conjugate = _("If we don't conjugate verbs correctly, the data will tell us how to do it right the next time."),
                      # Login to the website and try the system
                      tryit = _("Login and try it"),
                      # Login to the website. Stop using flash cards to learn the language.
                      ditch = _("Login. Ditch the flash cards."),
                      # You get a quota of 300MB on the website.
                      upload = _("Upload up to 300MB of literature for free."),
                      # Mobile device is free and does not have a limit or a quota.
                      unlimited = _("Unlimited content on your mobile devices."),
                      # We made something that you have never seen before
                      experience = _("The language experience you didn't know existed"),
                      # You get a quota of 300MB on the website.
                      upto = _("Free up to 300MB"),
                      # You pay for content, not for subscription.
                      payonly = _("Pay only for the content that you import."),
                      # Invitation to the user to donate money to get more space.
                      donate = _("Donate if you'd like additional space"),
                      # Analytics is a technology term for when the software tries to make a prediction about you based on data and patterns.
                      analytics = _("Analytics"),
                      # You learn by reading stories in context. We track those words and statistics across all the stories that you import into the system.
                      incontext = _("Learn in context. Words and statistics are cross-referenced across stories"),
                      # This means that we make the mobile application a priority.
                      alwaysmobile = _("Always mobile"),
                      byfar = _("Your device is by far the best way to use the system. Read on a tablet. Chat on your phone"),
                      # Our software, design, and algorithms are open-source.
                      designs = _("Our designs and algorithms are open for all to see"),
                      # Try the system
                      checkitout = _("Check it out"),
                      # You choose the complexity by importing whatever you want
                      youchoose = _("You choose the complexity"),
                      byimporting = _("By importing your own stories, you don't depend on us to provide them for you"),
                      # 'assistance' means the data vocabulary assists you while you are chatting
                      chatwith = _("Chat with assistance"),
                      # Same as previous comment: the data vocabulary assists you while you are chatting
                      instantmessaging = _("Instant messaging that's smart enough to read your own vocabulary in real-time."),
                      # Button to click to learn more about how the system works
                      learnmore = _("Learn More"),
                      # This is a technology phrase: It means that a website is designed with a priority to run a mobile device and a priority to be able to run offline without the need for an internet connection.
                      readyready = _("Mobile-ready. Offline-ready."),
                      # The software knows how to keep the website and the mobile device synchronized together
                      synchronized = _("Synchronized across all your devices."),
                      # This means that the mobile device works offline while you are using the system.
                      take = _("Take languages offline and on-the-go."),
                      # This software is open source
                      openforall = _("Open-source language for all."),
                      # A 'tech stack' is a technology term that refers to a list of all the different technologies used to build the software.
                      techstack = _("Tech Stack"),
                      # This is a standard copyright message at the bottom of the website.
                      reserved = _("All Rights Reserved."),
                      )
        return tag

    @renderer
    def error(self, request, tag) :
        return MessagesElement(self.req)

    @renderer
    def pages(self, request, tag) :
        pages = [
            _("<b>Read Alien</b> is a <b>new way</b> to learn a language."),
            _("Instead of hiring folks to <b>slave over</b> databases of translations,"),
            _("Why can't we use the <b>existing content</b> that's already out there?"),
            _("Like <b>books</b>, blogs, new articles, and eventually <b>social media</b>."),
            _("Read Alien works by <b>analytics</b>: You read <b>existing</b> books or stories and it <b>tracks your brain</b>."),
            _("When you read a new story, it <b>hides the words</b> you already know."),
            _("It knows how to track <b>polymphones and tones</b> in a Character-based language."),
            _("Read Alien is not a translator. It makes you <b>learn by reading</b> in context."),
            _("Flashcards are stupid. <br/><b>Try Read Alien!</b> and learn a new language."),
        ]

        first = True

        for page in pages :
            if first :
                first = False
                div = tags.div(**{"class" : "item active", "style" : "text-align: center"})
            else :
                div = tags.div(**{"class" : "item", "style" : "text-align: center"})

            div(tags.br(), tags.br(), tags.br())
            if isinstance(page, unicode) :
                page = page.encode("utf-8")
            p = XMLString("<div>" + unicheck(page) + "</div>")
            div(tags.h1(style="margin: 0 auto; width: 70%")(p.load()))
            div(tags.br(), tags.br(), tags.br())

            tag(div)

        return tag


class EditElement(CommonElement) :
    @renderer
    def edit(self, request, tag) :
        tag.fillSlots(editname = _("Legend"),
                      nb_page = self.req.page,
                      uuid = self.req.uuid,
                      # Chinese-only: merge/split means that we are indicating to the user that a particular group of characters was either split into separate characters or that a group of characters was merged into a single group
                      previousmerge = _("These characters were previously merged into a word"),
                      previoussplit = _("This word was previously split into characters"),
                      #  Chinese-only: These recommendations are edit-mode recommendations offered by the software to bulk-process SPLIT/MERGE operations that have been discovered by analyzing the user's previous edit history.
                      tryrecco = _("Try Recommendations"),
                      # Re-translate the current page that the user is reading right now.
                      repage = _("Re-translate page"),
                      # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
                      editdisabled = _("Edit history Disabled."),
                      # This history consists of an itemized list of words on the right-hand side of the page in Edit mode which have previously split or merged.
                      noedits = _("No edit history available."),
                      # Chinese-only: MERGE is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
                      merge = _("MERGE"),
                      # Chinese-only: SPLIT is one of two options in "Edit" mode: split or merge. This is only used for character-based languages, like, Chinese where a word can consist of more than one individual character. In these cases, the software helps the user to selectively split words apart into separate characters or merge characters together into a single word.
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
                      spinner = tags.img(src=self.req.mpath + '/' + spinner, width='15px'),
                      stats = stats,
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
                      # This is a button that appears in 'Reading' mode and allows the story to show only the text intead of the original book's picture or the original story's picture
                      textclasstitle = _("show text only"),
                      # This is a button that appears in 'Reading' mode and allows the user to show both the original book's picture and text side-by-side in the same window
                      bothclasstitle = _("side-by-side text and image"),
                      # This is a button that appears in 'Reading' mode and allows the user to show only the original book's picture without the text
                      imageclasstitle = _("show image only"),
                      # This is a button that tells the software to go and translate the words that were selected by the user
                      processinstanttitle = _("instant translation of one or more words"),
                      # This is a button that allows the user to toggle/hide/show the translations of all the words in the story.
                      meaningclasstitle = _("show/hide translations"),
                      # Chinese-only: This appears when a user wants to split/merge characters into a single group or into separate groups
                      processsplits = splits, processmerges = merges, processsplitstitle = _("Split this word into multiple characters"), processmergestitle = _("Merge these characters into a single word"),
                      # Refresh the current webpage
                      refreshtitle = _("Refresh"),
                      resultshow = 'display: block' if self.req.viewpageresult else 'display: none',
                      result = (self.req.viewpageresult + ".") if self.req.viewpageresult else '',
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
            # This is a title for a section indicating that we are allowing the user to download certain language dictionaries offline to be used with the mobile application.
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
        pull, push = self.pullpush()
        diskstat = str(self.req.disk_stat) + " MB"
        quotastat = (str(self.req.quota_stat) if self.req.quota_stat != -1 else "unlimited") + " MB"
        tag.fillSlots(
                        account = _("Account"),
                        username = self.req.session.value["username"],
                        offline = _("Offline dictionaries are required for using 'Edit' mode of some character-based languages and for re-translating individual pages in Review mode. Instant translations require internet access, so you can skip these downloads if your stories have already been edited/reviewed and you are mostly using 'Reading' mode. Each dictionary is somewhere between 30 to 50 MB each"),
                        # Change the mobile application zoom level
                        changeview = _("Change Viewing configuration"),
                        # Change the number of characters per line
                        charperline = _("Characters per line"),
                        perline = self.req.chars_per_line,
                        # Button to change 'something'. General button.
                        change = _("Change"),
                        # Change a user's quota on the website
                        changequota = _("Change Quota"),
                        # Mobile application default zoom level
                        zoom = _("Default zoom level"),
                        defaultzoom = self.req.default_zoom,
                        # Button to change 'something'. General button.
                        zoomchange = _("Change"),
                        # Switch the system interface to what language?
                        language =_("Language"),
                        # Switch the system interface to what language?
                        changelang = _("Change Language"),
                        # 'Learning language' refers to the language that the user is trying to learn 
                        learninglanguage = _("Learning Language"),
                        # 'Learning language' refers to the language that the user is trying to learn 
                        changelearnlang = _("Change Learning Language"),
                        # Cleanup the database
                        compact = _("Compact databases"),
                        # Change your password
                        changepass = _("Change Password"),
                        # change your email address
                        changeemail = _("Email Address"),
                        email = self.req.user["email"] if "email" in self.req.user else _("Please Provide"),
                        emailchange = _("Please change your email address on the website. Will support mobile in a future version"),
                        # change your email address
                        changemail = _("Change Email"),
                        deleteaccount = _("Delete Account?"),
                        # Wipe the mobile application's data and start over
                        mobiledelete = _("Reset application to defaults"),
                        # Old password for changing your password
                        oldpassword =_("Old Password / Token"),
                        # New password for changing your password
                        password = _("New Password / Token"),
                        # Confirm New password for changing your password
                        confirm = _("Confirm Password / Token"),
                        # change your password
                        passchange = _("Change Password / Token"),
                        # reset your password if you forgot it
                        reset = _("Reset Password / Token"),
                        passonline = _("Please change your password on the website. Will support mobile in a future version."),
                        # List of user accounts
                        accounts = _("Accounts"),
                        resultshow = 'display: block; padding: 10px' if self.req.accountpageresult else 'display: none',
                        result = (self.req.accountpageresult + ".") if self.req.accountpageresult else '',
                        # Button to delete something
                        delete = _("Delete"),
                        pull = pull,
                        push = push,
                        diskstat = diskstat,
                        quotastat = quotastat,

                     )
        return tag

class HTMLElement(CommonElement):
    @renderer
    def html(self, request, tag) :
        tag.fillSlots(
                     jqmcss = self.req.mpath + "/jquery.mobile.structure-1.4.5.min.css",
                     jqmtheme = self.req.mpath + "/jqmica/jqmica.min.css",
                     jqmthemeicons = self.req.mpath + "/jqmica/jquery.mobile.icons.min.css",
                     bootmincss = self.req.bootstrappath + "/dist/css/bootstrap.min.css",
                     micacss = self.req.mpath + "/mica.css",
                     favicon = self.req.mpath + "/icon-120x120.png",
                     imecss = self.req.mpath + "/chinese-ime/ime.css",
                     conversecss = self.req.mpath + "/converse.min.css",
                     jquery = self.req.mpath + "/jquery-1.11.3.min.js",
                     jquery_full = self.req.mpath + "/jquery-1.11.3.js",
                     micajs = self.req.mpath + "/mica.js",
                     bootminjs = self.req.bootstrappath + "/dist/js/bootstrap.min.js",
                     jqmjs = self.req.mpath + "/jquery.mobile-1.4.5.min.js",
                     xmpp = self.req.mpath + "/JSJaC-dec-2014/JSJaC.js",
                     ime = self.req.mpath + "/chinese-ime/jQuery.chineseIME.js",
                     bootpagejs = self.req.bootstrappath + "/js/jquery.bootpag.min.js",
                     caret = self.req.mpath + "/chinese-ime/caret.js",
                     chatjs = self.req.mpath + "/chat.min.js",
                     chatjsfull = self.req.mpath + "/chat.js",
                     converse = self.req.mpath + "/converse.min.js",
                     conversefull = self.req.mpath + "/converse-1.0.3.js",
                     chat = _("Chat"),
                     couchjs = self.req.mpath + "/jquery.couch-1.5.js",
                     alltitle = _("Read Alien: Meta Language Learning"),
                     companyname = _("Read Alien"),
                     ajaxformjs = self.req.mpath + "/jquery.form.min.js",
                     lazyyoutubecss = self.req.mpath + "/lazyyoutube.css",
                     lazyyoutubejs = self.req.mpath + "/lazyyoutube.js",
                     crewcss = self.req.mpath + "/crewcss/crew.min.css",
                    )

        return tag

class LoginElement(CommonElement):
    @renderer
    def form(self, request, tag) :
        tag.fillSlots(
                      # name of the ocmpany
                      softwarename = _("Read Alien Learning"),
                      # 'Sign in with' a specific social network, like facebook or google
                      signinwith = _("Sign in with"),
                      # A 'local' account is an account that does not use a social network, like facebook or google.
                      username = _("OR Use a local account") if not mobile else _("Account"),
                      # type your password
                      password = _("Password / Token"),
                      # An address is a website address for the location of the database.
                      address = _("Address"),
                      # This appears on the front page when you login and indicates whether to remember your username the next time you logout/login.
                      rememberme = _("Remember Me"),
                      # Button to login to the website
                      signin = _("Login"),
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
        pull, push = self.pullpush()
        viewstat = self.req.view_percent
        if viewstat == "100.0" :
            viewstat = "100"
        diskstat = str(self.req.disk_stat) + " MB"
        quotastat = (str(self.req.quota_stat) if self.req.quota_stat != -1 else "unlimited") + " MB"

        tag.fillSlots(
                     mobile = 'true' if mobile else 'false',
                     # Message on the mobile device when a story is imported for the first time.
                     pleaseinitonline = _("Story imported. Please initialize it on the website."),
                     # History of chat messages with other users
                     chatting = _("Chat History"),
                     # Button to show a user's chat history
                     storyrotate = _("Chat History"),
                     # Label indicating a list of stories that have not finished being reviewed
                     notreviewed = _("Reviewing"),
                     # Label indicating a list of stories that a user is currently reading
                     reading = _("Reading"),
                     # This appears in the side-panel when a story was just uploaded and has not yet been processed for reviewing yet.
                     untranslated = _("Untranslated"),
                     # Label indicating a list of stories that a user is finished with
                     finished = _("Finished"),
                     # List of all stories
                     stories = _("Stories"),
                     email = _("Email Address"),
                     # The next series of messages occur in a dialog used to upload a new story. Stories can be uploaded by copy-and-paste or by PDF, currently and the user can choose a number of languages.
                     userlang = _("Preferred Language"),
                     # Character-based languages do not have a lot of spaces, so we provide an option to remove them before translation and review.
                     removespaces = _("Remove Spaces?"),
                     # Account username to login with
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
                     # This appears in the left-hand pop-out side panel and allows the user to begin conversion of a newly uploaded story into our learning format.
                     translate = _("Translate"),
                     # 'Review' is a mode in which the software operates and is the first of 4 main buttons on the top-most navigation panel
                     reviewmode = _("Review"),
                     # 'Edit' is a mode in which the software operates and is the second of 4 main buttons on the top-most navigation panel
                     editmode = _("Edit"),
                     mpath = self.req.mpath + '/icon-120x120.png',
                     pull = pull,
                     push = push,
                     viewstat = viewstat,
                     diskstat = diskstat,
                     quotastat = quotastat,
                     # Preferences is located inside the 'Account' drop-down on the top-most navigation panel. It presents all the various preferences that can be permanently stored on the user's account.
                     preferences = _("Preferences"),
                     # Disconnect means the same as "logout" or "sign out" and is located inside the 'Account' dropdown on the top-most navigation panel.
                     disconnect = _("Logout"),
                     # About is a traditional description of the software package itself that you might find in other help menus of other programs.
                     about = _("About"),
                     # Help is not the usual 'help' in a software program. Instead it takes you directly to a tutorial about exactly how the software works.
                     help = _("Help"),
                     # The software's privacy policy, such as what user information we keep and do not keep.
                     privacy = _("Privacy"),
                     uploadstory = _("New Story"),
                     # Make a new account, a button inside the 'Account' section of the top-most navigation panel
                     newaccount = _("New Account"),
                     # Navigation label to click to switch to the chat window
                     chat = _("Chat"),
                     # Navigation label to click to learn a story / view the story for learning. 
                     learn = _("Learn"),
                     # The result of an instant translation of one or more words that the user has clicked on.
                     instant = _("Instant Translation"),
                     # A status message indicating that the system has gone to the internet to perform a translations of one or more words requested by the user.
                     performingtranslation= _("Doing instant translation..."),
                     spinner = tags.img(src=self.req.mpath + '/' + spinner, width='15px'),
                     token = self.req.session.value['cookie'] if not mobile else self.req.session.value['password'],
                     creds = self.req.credentials,
                     database = self.req.database,
                     authtype = "cookie" if not mobile else "pass",
                     # Label indicating a list of 'new' stories that have just been uploaded / imported into the website
                     newstory = _("New"),
                     # Button allowing the user to initialize a new story that has just been uploaded / imported into the website.
                     storyinit = _("Initialize Story"),
                     # This is a label the appears on the results of an instant translation that indicates which part of the translation came from an online database instead of an offline database. 
                     onlineinstant = _("Online instant translation"),
                     # This is the actual translation result of all the words put together
                     selectedinstant = _("Selected instant translation"),
                     # This is a label that takes the online instant translation and breaks the words into individual pieces.
                     piecemealinstant = _("Piecemeal instant translation"),
                     # This is a label the appears on the results of an instant translation that indicates which part of the translation came from an offline database instead of an online database. 
                     offlineinstant = _("Offline instant translation"),
                     # We were not able to find any translations for the words that were requested.
                     noinstant = _("No instant translation found."),
                     )
        return tag

def run_template(req, which, content = False) :
    try :
        if content :
            obj = which(req, content)
        else :
            obj = which(req)
    except Exception, e :
        for line in format_exc().splitlines() :
            mwarn(line)
        merr("Failed to instantiate element: " + str(e) + " \n" + str(content))
        raise e

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

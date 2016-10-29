var Base64={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(e){var t="";var n,r,i,s,o,u,a;var f=0;e=Base64._utf8_encode(e);while(f<e.length){n=e.charCodeAt(f++);r=e.charCodeAt(f++);i=e.charCodeAt(f++);s=n>>2;o=(n&3)<<4|r>>4;u=(r&15)<<2|i>>6;a=i&63;if(isNaN(r)){u=a=64}else if(isNaN(i)){a=64}t=t+this._keyStr.charAt(s)+this._keyStr.charAt(o)+this._keyStr.charAt(u)+this._keyStr.charAt(a)}return t},decode:function(e){var t="";var n,r,i;var s,o,u,a;var f=0;e=e.replace(/[^A-Za-z0-9\+\/\=]/g,"");while(f<e.length){s=this._keyStr.indexOf(e.charAt(f++));o=this._keyStr.indexOf(e.charAt(f++));u=this._keyStr.indexOf(e.charAt(f++));a=this._keyStr.indexOf(e.charAt(f++));n=s<<2|o>>4;r=(o&15)<<4|u>>2;i=(u&3)<<6|a;t=t+String.fromCharCode(n);if(u!=64){t=t+String.fromCharCode(r)}if(a!=64){t=t+String.fromCharCode(i)}}t=Base64._utf8_decode(t);return t},_utf8_encode:function(e){e=e.replace(/\r\n/g,"\n");var t="";for(var n=0;n<e.length;n++){var r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r)}else if(r>127&&r<2048){t+=String.fromCharCode(r>>6|192);t+=String.fromCharCode(r&63|128)}else{t+=String.fromCharCode(r>>12|224);t+=String.fromCharCode(r>>6&63|128);t+=String.fromCharCode(r&63|128)}}return t},_utf8_decode:function(e){var t="";var n=0;var r=c1=c2=0;while(n<e.length){r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r);n++}else if(r>191&&r<224){c2=e.charCodeAt(n+1);t+=String.fromCharCode((r&31)<<6|c2&63);n+=2}else{c2=e.charCodeAt(n+1);c3=e.charCodeAt(n+2);t+=String.fromCharCode((r&15)<<12|(c2&63)<<6|c3&63);n+=3}}return t}}
var chat_username = false;

/*
 * Only functions defined in the main HTML page
 * seem to be visible from Android. No idea why.
 */
function pushstat(info) {
    console.log("Setting push to " + info);
    if (info == "100.0")
        info = "100";
    $("#pushstat").html(info);
    $("#pushstat2").html(info);
    $("#pushstat3").html(info);
}
function pullstat(info) {
    console.log("Setting pull to " + info);
    if (info == "100.0")
        info = "100";
    $("#pullstat").html(info);
    $("#pullstat2").html(info);
    $("#pullstat3").html(info);
}
function viewstat(info) {
    if (info == "100.0")
        info = "100";
    $("#viewstat").html(info);
    $("#viewstat2").html(info);
}

function diskstat(info) {
    $("#diskstat").html(info + " MB");
    //$("#viewstat2").html(info);
}

function local(msgid) {
    return $("#" + msgid).html();
}

function switchinstall(initlist) {
	list_mode = initlist;
	if (list_mode) {
	       $("#switchlisttext").html(local('statsshown'));
	} else {
	       $("#switchlisttext").html(local('statshide'));
	}
}

function switchlist_complete(json, opaque) {
    done();
    if (json.success) {
       switchinstall(json.list_mode);
       listreload(current_mode, current_uuid, current_page);
    } else {
        alert(json.desc);
    }
}

function switchlist() {
   go(false, 'home&switchlist=' + (list_mode ? '0' : '1'), unavailable(false), switchlist_complete, false);
}

$("[data-role='header'],[data-role='footer']").toolbar();
$("[data-role='panel']").panel().enhanceWithin();

//$.mobile.ignoreContentEnabled = true;
//$(document).bind("mobileinit", function(){
//        $.extend(  $.mobile , { ajaxEnabled: false });
//});

/*
$.mobile.loading("hide");
$(".ui-loader").hide();
*/

//$("#sidebarcontents").panel({beforeopen: function(event, ui) {loadstories(false);}});

chat_loaded = false;

function chat_success(json, opaque) {
    if (json.success) {
        $("#chat_content").html(json.desc);
    } else {
        // This is an error. Do something better with the print here.
        $("#chat_content").html(json.desc);
    }
    chat_loaded = true;
}

var learn_loaded = false;

function learn_success(json, opaque) {
    if (json.success) {
        learn_loaded = true;
        $("#learn_content").html(json.desc);
        install_pages_if_needed(json);
        if ($("#learn_content").html() == "") {
           $.mobile.navigate("#messages");
        }
    } else {
        alert(json.desc);
    }
}

function form_loaded_complete(data, opaque) {
    done();
    $('#compactModal').modal('hide');
    $('#regroupModal').modal('hide');
    $('#reviewModal').modal('hide');
    form_loaded(data, true);
}

function form_loaded(data, do_forms) {
    $.mobile.silentScroll(0);
    if (do_forms) {
        $("form.ajaxform").each(function() {
            var destid ='';
            $(this).off().on("submit", function(event, form) {
              loading();
              event.preventDefault();
              var aff = $(form).attr('ajaxfinish');
              if(form && aff == undefined) {
                    var closest = $(form).closest("[data-role='content']");
                    var destid = "#" + closest.attr('id');
                    if (destid == "#undefined")
                        destid = "#" + $(form).attr('ajaxfinishid');
              }
              go([form, destid], 'url_comes_from_form', unavailable(false), form_loaded_complete, true);
            });
            $(this).find(":submit").off().on("click", function(event) {
                    event.preventDefault();
                    myform = $(this).closest("form");
                    myform.trigger('submit', myform);
            });
        });
    } else {
        done();
    }
}

function loading() {
    $.mobile.loading( "show", {
        text: "Loading",
        textVisible: true,
        theme: "z",
        html: ""
    });
}

function done() {
    $.mobile.loading('hide');
}

$(document).on("pagecontainershow", function (e, data) {
    done();
});

function account_complete(json, opaque) {
    $("#account_content").html(json.desc);
    form_loaded(json.desc, opaque);
}

function help_complete(json, opaque) {
    $("#help_content").html(json.desc);
}

function privacy_complete(json, opaque) {
    $("#privacy_content").html(json.desc);
}

var firstpageload = true;

function reset_chat() {
    chat_loaded = false;
    first_reconnect = true;
    force_disconnect();
}

$(document).off("pagecontainerbeforechange").on("pagecontainerbeforechange", function (e, data) {
   if (typeof data.toPage == "string") {
        var where = data.toPage.split("#")[1];
        if (firstpageload && (where == "explode" || where == "reading" || where == "newstory" || where == "untranslated")) {
           where = "stories";
        }

        firstpageload = false;

        var from = $.mobile.pageContainer.pagecontainer("getActivePage").attr('id');
        if (from != where) {
           loading();
        } else {
            console.log("We're already on this page. What's the dealio?");
            if (from == "stories") {
                $("#storypages").html("");
            }
            return false;
        }
        console.log("Going to: " + where + " from " + from);
        if (where == 'stories') {
            loadstories(false, false);
        } else if (where == 'chat') {
            if ("Notification" in window && Notification.permission != 'denied') {
                Notification.requestPermission();
            }
            if (!chat_loaded) {
               go(false, 'chat', unavailable(false), chat_success, false);
            }
        } else if (where == 'learn') {
            if (!learn_loaded) {
               var pageid = "home";
               var lastmode = $("#lastmode");
               if (lastmode != undefined)
                    pageid = lastmode.html();

               go(false, pageid, unavailable(false), learn_success, false);
            }
        } else if (where == 'account') {
               loading();
               go(false, 'account', unavailable(false), account_complete, true);
        } else if (where == 'help') {
               go(false, 'help', unavailable(false), help_complete, false);
        } else if (where == 'privacy') {
               go(false, 'privacy', unavailable(false), privacy_complete, false);
        } else if (from != where) {
        //       $.mobile.navigate("#" + where);
               done();
        }
   }
   return true;
});

$(document).on("pagecreate", function () {
    $("[data-role=panel]").one("panelbeforeopen", function () {
        var height = $.mobile.pageContainer.pagecontainer("getActivePage").outerHeight();
        $(".ui-panel-wrapper").css("height", height + 1);
    });
});
$(document).on('ready', function() {
	$("div.view1").hide();

	$("div.slide1").click(function(){
		$("div.view1").slideToggle(400);
		$("div.tri1").toggleClass("toggle1");
	});
    form_loaded(false, true);
    switchstart();
});


function ScaleContentToDevice(){
    scroll(0, 0);
    var content = $.mobile.getScreenHeight() - $(".ui-header").outerHeight() - $(".ui-footer").outerHeight() - $(".ui-content").outerHeight() + $(".ui-content").height();
    $(".ui-content").height(content);
}

$(document).on( "pagecontainershow", function(){
//    ScaleContentToDevice();
});

$(window).on("resize orientationchange", function(){
 //   ScaleContentToDevice();
});

$(document).ready(function () {
	$(".modal").each(function() {
	    $(this).off().on('shown.bs.modal', function() {
		$(".affix").each(function() { $(this).removeClass('affix'); $(this).addClass('affix-top'); $(this).affix(); });
		
	    });
	    $(this).off().on('hidden.bs.modal', function() {
		$(".affix-top").each(function() { $(this).removeClass('affix-top'); $(this).addClass('affix'); $(this).affix(); });
		
	    });
	});
});

var translist = [];
$.couch.urlPrefix = $('#creds').html();
var db = $.couch.db($('#database').html());
var authorization = false;

if ($("#authtype").html() != undefined && $("#authtype").html() != 'cookie') {
   authorization = "Basic " + Base64.encode($("#username").html() + ":" + $('#token').html());
   console.log("Trying to login to local couch...");
   $.ajax({
        type: "GET",
        url: $('#creds').html() + "/_session",
        dataType: "json",
        xhrFields: {withCredentials: true},
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Accept", "application/json");
            xhr.setRequestHeader("Authorization", authorization);
        },
        complete: function(req) {
          if (req.status == 200) {
            console.log("Couch login success!");
          } else {
            console.log("Couch login failed.");
            var resp = $.parseJSON(req.responseText);
            alert("Failed to login to couch listener on mobile! " + req.status + " " + resp.error + " " + resp.reason);
          }
        }
    });
}

function showNotifications(msgfrom, msg, lang) {
    if ("Notification" in window) {
        if (Notification.permission == 'granted') {
            try {
                var notification = new Notification(local('notification') + ": " + msgfrom,
                    { dir: "auto",
                      body: msg,
                      lang: lang,
                      tag: "mica",
                      // Icon doesn't work. Try again later.
                      //icon : window.location.href.split("#")[0] + local('favicon'),
                    });
            } catch (e) {
                console.log("Couldn't make notification" + e);
            }
            // notification.onclose = …
            // notification.onshow = …
            // notification.onerror = …
        }
    }
}
function appendConverse(who, to, $message, obj, direction) {
    var ts = $.now();
    var tzoffset = ((new Date()).getTimezoneOffset()) * 60;

    var languagepair = $('#chattextlanguage').val();
    var pair = languagepair.split(",");
    var chat_source_language = pair[0];
    var chat_target_language = pair[1];
    var chat_language = chat_target_language;
    var msgfrom = who_to_readable(who);
    var msgto = who_to_readable(to);

    if (direction == "in") {
        msg = $message.children('body').text();
    } else {
        msg = $message;
    }
    /*
     * 'peer' means who we are talking to, regardless who the message comes from.
     *
     * If we have 'group' chats in the future, just set the 'peer' value to some kind
     * of unique ID, like "group_UUID". Simple one-on-one chats will have document keys
     * equal to the name of the peer, but with a group chat, we'll need to choose something
     * unique for the peer value. Theoretically, the server-side shouldn't change too much.
     */
    if (who == chat_username) {
        var peer = msgto;
        var msgclass = "msgright";
        var reverse = true;
    } else {
        var peer = msgfrom;
        var msgclass = "msgleft";
        var reverse = false;
    }

    var micaurl = "chat_ime&ime=1&mode=read&target_language=" + chat_target_language + "&source_language=" + chat_source_language + "&lang=" + chat_language + "&ime1=" + msg + "&start_trans_id=" + start_trans_id + "&ts=" + (ts - tzoffset) + "&tzoffset=" + tzoffset + "&msgfrom=" + msgfrom + "&msgto=" + msgto + "&peer=" + peer;

    start_trans_id += msg.length;

    go(false, micaurl, unavailable(false), function(json, obj){
            if (direction == "in") {
                if(json.success)  {
                    $message.children('body').text(json.result.human);
                } else {
                    $message.children('body').text(json.desc);
                }
                obj.__super__.onMessage.apply(obj, [$message.get()]);
            } else {
                var d = $("[data-msgid='" + direction + "']").find(".chat-msg-content");
                if(json.success)  {
                    d.html(json.result.human);
                } else {
                    d.html(json.desc);
                }
                obj.scrollDown();
            }
	}, obj);
}

function handleConnectedLoaded(json, opaque) {
    $("#pagechatsingle").html("");
    $("#iResp").prepend(json.desc);
    //$("#iResp").prop({ scrollTop: $("#iResp").prop("scrollHeight") });
}

function newContact(peer) {
    if($("#sendTo").val() == peer) {
        return;
    }
    $("#iResp").html("");
    $('#sendTo').val(peer);
    /* 
     * For some reason. Loading the history
     * made the IME stop working.
     * figure it out later.
     */
//    $("#pagechatsingle").html(spinner + "&nbsp;" + local("loadingtext"));
//    var tzoffset = ((new Date()).getTimezoneOffset()) * 60;
//    go(false, "chat&history=" + peer + "&tzoffset=" + tzoffset, unavailable(false), handleConnectedLoaded, false);
}

function reload_history(logincheck) {
    if (logincheck) {
        try {
            if (converse.connection.connected()) {
                converse.user.logout();
            }
        } catch (e) {
            console.log("Ignoring failed logout.");
            relogin(1);
        }
    }
    if ($('#sendTo').val() != "") {
        $("#login_pane").attr("style", "display: block");
        $("#chatLoading").attr("style", "display: block");
        $("#iResp").html("");
        document.getElementById('login_pane').style.display = 'none';
        document.getElementById('sendmsg_pane').style.display = '';
        document.getElementById('err').innerHTML = '';
        to = $('#sendTo').val();
        $('#sendTo').val("");
        newContact(to);
    }
}

var cparams;

/* This doesn't really work. Hard to get right. */
function relogin(attempt) {
    retimeout = 100;
    if (attempt > 0) {
        retimeout = 5000;
    }
    console.log("Setting timeout: " + retimeout + " secs.");
    setTimeout(function() {
        try {
            console.log("Checking connectedness.");
            if (converse.connection.connected()) {
                console.log("Still connected. Nothing to do.");
                return;
            }

            console.log("Disabling listeners.");
            converse.listen.not('disconnected');
            converse.listen.not('recconnected');
            console.log("Logging out.");
            converse.user.logout();
            console.log("Logging in.");
            converse.user.login();
//            converse.chats.get('controlbox').close();
        } catch (e) {
            console.log("Couldn't reconnect: " + e);
            try {
                converse.initialize(cparams);
            } catch (e) {
                console.log("Couldn't reinitialize either.");
            }
        }
        relogin(attempt + 1);
    }, retimeout);
}

function ctest() {
    var oForm = document.getElementById('loginForm');

    var server = oForm.server.value;
    var domain = oForm.domain.value;
    chat_username = oForm.username.value;
	jid = chat_username + "@" + domain;

    if ($("#mobile").html() == 'false' && window.location.protocol !== "https:"){
        console.log("Insecure chat.");
        httpbase = 'http://' + server + ':5280/http-bind/';
    } else {
        console.log("Secure chat.");
        httpbase = 'https://' + server + ':5281/http-bind/';
    }

    converse.plugins.add('mll', {

        initialize: function () {
            //alert(this.converse.user_settings.initialize_message);
        },

        overrides: {
            ChatBoxes: {
                onMessage: function (text) {
                    var $message = $(text);
                    if ($message != undefined) {
                        if ($message.attr('type') != 'error') {
                            var body = $message.children('body').text();
                            if (body != "") {
                                from = $message.attr('from').split("@")[0];
                                to = $message.attr('to').split("@")[0];
                                appendConverse(from, to, $message, this, "in");
                            }
                        }
                    }
                    return true;
                }
            },
            ChatBoxView: {
                onMessageSubmitted: function (text) {
                    var conv = this.__super__.converse;
                    if (!conv.connection.authenticated) {
                        return this.showHelpMessages(
                            ['Sorry, the connection has been lost, '+
                                'and your message could not be sent'],
                            'error'
                        );
                    }
                    var match = text.replace(/^\s*/, "").match(/^\/(.*)\s*$/), msgs;
                    if (match) {
                        if (match[1] === "clear") {
                            return this.clearMessages();
                        }
                        else if (match[1] === "help") {
                            msgs = [
                                '<strong>/help</strong>:'+__('Show this menu')+'',
                                '<strong>/me</strong>:'+__('Write in the third person')+'',
                                '<strong>/clear</strong>:'+__('Remove messages')+''
                                ];
                            this.showHelpMessages(msgs);
                            return;
                        }
                    }
                    var fullname = conv.xmppstatus.get('fullname');
                    fullname = _.isEmpty(fullname)? conv.bare_jid: fullname;
                    var message = this.model.messages.create({
                        fullname: fullname,
                        sender: 'me',
                        time: moment().format(),
                        message: text
                    });
                    this.sendMessage(message);
                    jid = this.model.get('jid');
                    to = jid.split("@")[0];
                    newContact(to);
                    appendConverse(chat_username, to, text, this, message.attributes.msgid);
                },
                renderMessage: function (attrs) {
                    var conv = this.__super__.converse;
                    var msg_time = moment(attrs.time) || moment,
                        text = attrs.message,
                        match = text.match(/^\/(.*?)(?: (.*))?$/),
                        fullname = this.model.get('fullname') || attrs.fullname,
                        extra_classes = attrs.delayed && 'delayed' || '',
                        template, username;

                    if ((match) && (match[1] === 'me')) {
                        text = text.replace(/^\/me/, '');
                        template = conv.templates.action;
                        username = fullname;
                    } else  {
                        template = conv.templates.message;
                        username = attrs.sender === 'me' && local('me') || fullname;
                    }
                    this.$content.find('div.chat-event').remove();

                    if (this.is_chatroom && attrs.sender === 'them' && (new RegExp("\\b"+this.model.get('nick')+"\\b")).test(text)) {
                        extra_classes += ' mentioned';
                    }
                    if (text.length > 10000) {
                        text = text.substring(0, 10) + '...';
                        this.showStatusNotification(local("largemessage"), true, true);
                    }

                    start_trans_id += text.length;

                    return $(template(
                            _.extend(this.getExtraMessageTemplateAttributes(attrs), {
                                'msgid': attrs.msgid,
                                'sender': attrs.sender,
                                'time': msg_time.format('hh:mm'),
                                'isodate': msg_time.format(),
                                'username': username,
                                'message': '',
                                'extra_classes': extra_classes
                            })
                        )).children('.chat-msg-content').first().html(text)
                            .addHyperlinks()
                            .addEmoticons(conv.visible_toolbar_buttons.emoticons).parent();
                }
            }
        }
    });

    converse.listen.on('initialized', function (event) { 
        console.log("WE ARE INITIALIZED");
    });
    converse.listen.on('connected', function (event) { 
        console.log("WE ARE CONNECTED");
        reload_history(false);
        converse.listen.on('disconnected', function (event) { 
            console.log("DISCONNECTED.");
            relogin(0);
        });
        converse.listen.on('reconnected', function (event) { 
            console.log("reconnected. Start all over");
            /*
            converse.chats.get('controlbox').close();
            converse.user.logout();
            converse.user.login({
                'jid': jid,
                'password': oForm.password.value
            });
            */
        });
    });

    converse.listen.on('chatBoxOpened', function (event, chatbox) {
        var cb = chatbox.$el.find("textarea.chat-textarea");
        if (cb.attr("ime") == undefined || cb.attr("ime") != "1") {
            cb.attr("ime", "1");
            var ci = cb.chineseInput({
                debug: false,
                input: {
                    initial: 'simplified',//'traditional', // or 'simplified'
                    allowChange: true
                },
                allowHide: true,
                active: true
            });
        }
    });

    /* TODO: use xhr_user_search and xhr_user_search_url options */
    cparams = {
        bosh_service_url: httpbase, 
        keepalive: true,
        prebind: true,
        prebind_url: "/api?human=0&alien=prebind",
        jid: jid,
        message_carbons: true,
        play_sounds: true,
        roster_groups: true,
        show_controlbox_by_default: false,
        allow_otr: false,
//        debug: true,
        allow_muc: false,
        allow_registration: false,
//        auto_reconnect: true,
        allow_logout: false,
//        auto_login: true, //prebind only
    };
    converse.initialize(cparams);

//    converse.user.login();
    /*
    if (converse.connection.connected && !converse.connection.authenticated) {
        converse_first_time = false;
        converse.user.login({
            'jid': jid,
            'password': oForm.password.value
        });
//        converse.chats.get('controlbox').close();
    } else if (!converse.connection.connected) {
        converse.user.logout();
    } else {
        converse_first_time = false;
        converse.user.login({
            'jid': jid,
            'password': oForm.password.value
        });
//        converse.chats.get('controlbox').close();
    }
    */
}


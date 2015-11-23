/* 
 * Only functions defined in the main HTML page
 * seem to be visible from Android. No idea why.
 */
function pushstat(info) {
    if (info == "100.0")
        info = "100";
    $("#pushstat").html(info);
}
function pullstat(info) {
    if (info == "100.0")
        info = "100";
    $("#pullstat").html(info);
}
function viewstat(info) {
    if (info == "100.0")
        info = "100";
    $("#viewstat").html(info);
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
       switchinstall(list_mode ? false : true);
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

learn_loaded = false;

function learn_success(json, opaque) {
    if (json.success) {
        learn_loaded = true;
        $("#learn_content").html(json.desc);
        install_pages_if_needed(json);
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

$(document).on("pagecontainerbeforechange", function (e, data) {
   if (typeof data.toPage == "string") {
       var where = data.toPage.split("#")[1];
       if (where == "explode" || where == "reading") {
           where = "stories";
       }
       var from = $.mobile.pageContainer.pagecontainer("getActivePage").attr('id');
       if (from != where) {
           loading();
       }
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
switchinstall(true);
$(document).on('ready', function() {
	$("div.view1").hide();

	$("div.slide1").click(function(){
		$("div.view1").slideToggle(400);
		$("div.tri1").toggleClass("toggle1");
	});
    form_loaded(false, true);
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
var token = encodeURIComponent($('#token').html());
$.couch.urlPrefix = $('#creds').html();
var db = $.couch.db($('#database').html()); 
var authtype = $("#authtype").html();
var username = encodeURIComponent($("#username").html());

/*
 * Note: When using 'login', the username/pass 
 * needs to be encoded, but for some reason,
 * the keys for things like 'openDoc' do not need that.
 */
if (authtype != 'cookie') {
   $.couch.login({name: username, password: token,
         error : function(stat, error, reason) {
            alert("Failed to login to couch listener on mobile! " + stat + " " + error + " " + reason);
        }
    });
}

function showNotifications(msgfrom, msg, lang) {
    if ("Notification" in window) {
        if (Notification.permission == 'granted') {
            try {
                var notification = new Notification("MICA Message from: " + msgfrom, 
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


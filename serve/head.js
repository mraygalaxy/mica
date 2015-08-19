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

function switchlist() {
   go(false, '#switchlisttext', '/api?alien=home&switchlist=' + (list_mode ? '0' : '1'), 
        '', unavailable, false, false, false);
   switchinstall(list_mode ? false : true);
   listreload(current_mode, current_uuid, current_page);
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

function chat_success(data) {
    chat_loaded = true;
    done();
}

learn_loaded = false;

function learn_success(data) {
    learn_loaded = true;
}

function form_loaded_finish(data, opaque) {
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
            $(this).on("submit", function(event, form) {
                loading();
                event.preventDefault();
                var closest = $(form).closest("[data-role='content']");
                var destid = "#" + closest.attr('id');
                if (destid == "#undefined")
                    destid = "#" + $(form).attr('id') + "content";
                var fromid = destid + "_result"; 
                go(form, destid, 'url_comes_from_form', fromid, unavailable, true, form_loaded_finish, true, true);
            });
            $(this).find(":submit").click(function(event) {
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

$(document).on("pagecontainerbeforechange", function (e, data) {
   if (typeof data.toPage == "string") {
        var where = data.toPage.split("#")[1];
        if (where == 'stories') {
            loading();
            loadstories(false, false);
        } else if (where == 'chat') {
                if (!chat_loaded) {
                   loading();
                   go(false, '#chat_content', '/api?alien=chat', '#chat_content_result', unavailable, true, chat_success, true, false);
                }
        } else if (where == 'learn') {
                if (!learn_loaded) {
                   var pageid = "home";
                   var lastmode = $("#lastmode");
                   if (lastmode != undefined)
                        pageid = lastmode.html();
                   go(false, '#learn_content', '/api?alien=' + pageid, '', unavailable, false, learn_success, true, false);
                }
        } else if (where == 'account') {
               loading();
               go(false, '#account_content', '/api?alien=account', '', unavailable, false, form_loaded, true, true);
        } else if (where == 'help') {
               go(false, '#help_content', '/api?alien=help', '#helpresult', unavailable, true, false, true, false);
        } else if (where == 'privacy') {
               go(false, '#privacy_content', '/api?alien=privacy', '#privacyresult', unavailable, true, false, true, false);
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

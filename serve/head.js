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
   go('#switchlisttext', '/home?switchlist=' + (list_mode ? '0' : '1'), '', unavailable, false, false, false);
   switchinstall(list_mode ? false : true);
   listreload(current_mode, current_uuid, current_page);
}

$("[data-role='header'],[data-role='footer']").toolbar();
$("[data-role=panel]").panel().enhanceWithin();

$(document).bind("mobileinit", function(){ $.extend(  $.mobile , { ajaxEnabled: false });});

/*
$.mobile.loading("hide");
$(".ui-loader").hide();
*/

//$("#sidebarcontents").panel({beforeopen: function(event, ui) {loadstories(false);}});

$(document).on("pagecreate", function () {
    $("[data-role=panel]").one("panelbeforeopen", function () {
        var height = $.mobile.pageContainer.pagecontainer("getActivePage").outerHeight();
        $(".ui-panel-wrapper").css("height", height + 1);
    });
});

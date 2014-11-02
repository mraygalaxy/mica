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

var ConnectisVisible = false;
var ConnectclickedAway = false;
function getTemplate() {
        if ($.browser.device == true)
                return "<div style='margin-right: 150px' id='connectpopover' class='popover'><div class='arrow'></div><div class='popover-inner'><h3 class='popover-title'></h3><div class='popover-content'><p></p></div></div></div>";
        else
                return "<div id='connectpopover' class='popover'><div class='arrow'></div><div class='popover-inner'><h3 class='popover-title'></h3><div class='popover-content'><p></p></div></div></div>";
}
var connectpop = $('#connectpop').popover({ 
    html : true,
    title: "Connect:",
    placement : 'bottom',
    trigger: 'manual',
    template: getTemplate(),
    content: function() {
      return $('#ConnectContents').html();
    }
  });

   ConnectclickedAway = true;
   ConnectisVisible = true;

  connectpop.click(function(e) {
        $(this).popover('toggle');
        ConnectclickedAway = false;
        ConnectisVisible = true;
        e.preventDefault();
    });

$(document).click(function(e) {
     if (typeof WL == 'undefined') {
          var src = e.target;
     } else {
          var src = e.srcElement;
     }
     if(findParentNode('ConnectContents', src, 'cbody') == true) {
         return;
     }
     if(findParentNode('connectpopover', src, 'cbody') == true) {
         return;
     }

     if(ConnectisVisible & ConnectclickedAway)
     {
        $('#connectpop').popover('hide');
        ConnectisVisible = ConnectclickedAway = false;
     } else {
        ConnectclickedAway = true;
     }
});

$(document).ready(function(){
    $("div.view1").hide();
    
    $("div.slide1").click(function(){
        $("div.view1").slideToggle(400);
        $("div.tri1").toggleClass("toggle1");
    });
    
});

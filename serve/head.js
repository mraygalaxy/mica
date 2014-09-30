/* 
 * Only functions defined in the main HTML page
 * seem to be visible from Android. No idea why.
 */
function pushstat(info) {
    $("#pushstat").html(info);
}
function pullstat(info) {
    $("#pullstat").html(info);
}
function viewstat(info) {
    $("#viewstat").html(info);
}
    function switchinstall(initlist) {
        list_mode = initlist;
        if (list_mode) {
               $("#switchlisttext").html('Stats Shown');
        } else {
               $("#switchlisttext").html('Stats Hidden');
        }
    }

    function switchlist() {
           go('#switchlisttext', bootdest + '/home?switchlist=' + (list_mode ? '0' : '1'), '', unavailable, false, false, false);
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

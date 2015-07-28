/*
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
*/

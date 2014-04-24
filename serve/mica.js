  debugger;
var bootdest = "";
//var bootdest = window.location.href.match(/[^/]*\/([^/]*)/g)[2];
var last_data = '';
var first_time = true;
var debug = false;
//var debug = true;
var unavailable = "error!";
var prmstr = window.location.search.substr(1);
var prmarr = prmstr.split ("&");
var params = {};
var heromsg = "<div class='hero-unit' style='padding: 5px'>";
for ( var i = 0; i < prmarr.length; i++) {
    var tmparr = prmarr[i].split("=");
    params[tmparr[0]] = tmparr[1];
}
var active = "app";
var liststate = "all";

var spinner = "<img src='data:image/gif;base64,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' width='20px'>";

if ("object" in params)
    active = params["object"];
    
if ("liststate" in params)
    liststate = params["liststate"];

  var do_refresh = false;
  var secs = 20;
  var failcount = 0;
  var newRefresh = 0;
  var finish = false;
  function populateRefreshChoices() {
      e = document.getElementById('changerefresh');
      e.options.length=0;
      for(x = 0; x < (parseInt(secs) + 60); x++) {
          e.options[x] = new Option(x, x);
          if (x == secs)
              e.options.selectedIndex = x;
      }    
  }
  function doNewRefresh() {
      e = document.getElementById('changerefresh');
      newRefresh = e.options[e.selectedIndex].value;
      secs = newRefresh;
      populateRefreshChoices();
  }

  function go(id, url, getSpecificContent, error, writeSubcontent, callback, write){
      jQuery.support.cors = true;
      jQuery.ajax({
        url: url,
        type: "GET",
        dataType: "html",
        error: function (XMLHttpRequest, ajaxOptions, thrownError) {
              if(XMLHttpRequest.statusText == 'error') {
                  $(id).html("<div class='hero-unit' style='padding: 5px'><h4>" + spinner + "&nbsp;&nbsp;" + error + "</h4></div>");
              }
             if(callback != false)
               callback('error');
        },
        success: function (response) {
            var data = "none";
            if(response.indexOf("<h4>Exception:</h4>") != -1 && response.indexOf("<h4>") != -1) {
                $(id).html(response);
            } else {
	            if(getSpecificContent != '') {
	                data = $(response).find(getSpecificContent).html();
	                if(write) {
	                    if(writeSubcontent)
	                        $(id).html(data);
	                    else
	                        $(id).html(response);
	                }
	            } else {
	                if(write)
	                    $(id).html(response);
	                data = response;
	            }
	            if(callback != false)
	               callback(data);
            }
        }
      });
  }

  function CountBack(id, barid, left, opaque) {
    if(do_refresh) {
        if(left >= 0) {
            newSecs = left - 1;
            if(newRefresh) {
              newSecs = newRefresh;
              newRefresh = 0;
            }
            if(id != false && id != 'false')
                document.getElementById(id).innerHTML = 'Next Check: ' + left;
            if(left != 0 && barid != false && barid != 'false')
                document.getElementById(barid).style.width = ((secs - left) / secs) * 100 + "%";
            setTimeout("CountBack('" + id + "', '" + barid + "', " + newSecs + ", '" + opaque + "');", 990);
        } else {
          if(finish != false) 
              finish(opaque);
        }
    } else {
        if(id != false && id != 'false')
            document.getElementById(id).innerHTML = '';
    }
  }


function trans_wait_poll(uuid) {
    if (first_time) {
        secs = 10;
    } else {
        secs = 5;
    }
    first_time = false;
    CountBack(false, false, secs, uuid);
}

var first_time = false; 

function trans_poll_finish(data, uuid, unused) {
    var tmparr = data.split(" ");
    var result = tmparr[0];
    var percent = tmparr[1];

    if (result == "yes" || first_time) {
        $("#translationstatus" + uuid).html(spinner + "&nbsp;&nbsp;Working: " + percent + "%");
        trans_wait_poll(uuid);
    } else {
        $("#translationstatus" + uuid).html('Done! Please reload.');
    }
}

function trans_poll(uuid) {
   change('',
       bootdest + '/home?tstatus=1&uuid=' + uuid, 
       '#tstatusresult',
       unavailable, 
       false, 
       trans_poll_finish, 
       false,
       uuid,
       false);
} 

function trans_stop(data, uuid, unused) {
    finish = false;
    do_refresh = false;
    $("#translationstatus" + uuid).html('Done! Please reload.');
}

function trans_start(uuid) {
    $("#transbutton" + uuid).attr("style", "display: none");
    do_refresh = true;
    first_time = true;
    finish = trans_poll;
    trans_poll(uuid);
    $("#translationstatus").html(spinner + "&nbsp;Stories in translation...");
    $("#translationstatus" + uuid).html(spinner + "&nbsp;Translating...");
}

function trans(uuid) {
   trans_start(uuid);
   change('#translationstatus', 
       bootdest + '/home?translate=1&uuid=' + uuid, 
       '#translationstatusresult', 
       unavailable, 
       true, 
       trans_stop,
       true,
       uuid,
       false);
}
  function resetMonitor(data) {
      if(data != 'error') {
          htmlobj = $(data);
          $("#summary").html(htmlobj.find("#monitorsummary"));
          htmlobj = $(data);
          $("#taball").html(htmlobj.find("#monitordata"));
          htmlobj = $(data);
          var choices = new Array('p', 'h', 's', 'a');
          var x = 0;
          for(x = 0; x <=3 ; x++) {
              y = choices[x];
              htmlobj = $(data);
              result = htmlobj.find("#monitor" + y);
              if((result.html() + "") == "null")
                  $("#tab" + y).html("<h3>This performance category is not configured. <a href='monitordata'>Try loading the data directly</a> to see if there are any python errors. Click 'Options' to activate.</h3>");
              else
                  $("#tab" + y).html(result);
          }
      } else {
          $("#summary").html("<h4 style='color: red'>CloudBench is unavailable. Will try again later...</h4>");
      }
      finish = checkMonitor;
      do_refresh = true;
      CountBack('count', 'countbar', secs);
  }
  function startRefresh() {
      checkMonitor();
      $('#refreshButton').button('disable');
      $('#refreshButton').on('click', stopRefresh);
  }
  function stopRefresh() {
      do_refresh = false;
      $('#refreshButton').button('enable');
      $('#refreshButton').on('click', startRefresh);
  }

function poll(s, finisher, monid) {
        secs = s;
        do_refresh = true;
        finish = finisher;
        if(debug)
            CountBack(monid, false, s);
        else
            CountBack(false, false, s);
}

function check_nodraw() {
   go('#pendingtest', bootdest + '/provision?pending=1&object=' + active, '#pendingresult', unavailable, true, pending_callback, false);
}
function pending_callback(data) {
        if (!debug && last_data == '')
            $('#pendingcount2').html('');
        if(data == 'unchanged') {
            if(debug)
                $('#pendingcount2').html('result: unchanged ' + last_data);
            if(last_data == 'No Pending Objects') {
				go('#allstate', bootdest + '/provision?allstate=1&liststate=' + liststate + '&object=' + active, '#allstate', unavailable, true, false, true);
                poll(30, check_nodraw, 'pendingcount');
            } else {
                poll(3, check_nodraw, 'pendingcount');
            }
        } else if(data == 'error' || data == 'none' || data == 'No Pending Objects') {
            last_data = '';
            $('#pendingtest').html('');
            //$('#pendingstatus').html('');
            if("operation" in params) {
               $('#pendingtest').html(heromsg + "<h4>&nbsp;&nbsp;Request(s) Complete.</h4></div>");
            }
            if(data == 'error') {
                first_time = true;
                poll(1, check_pending, 'pendingcount');
            } else if (data == 'No Pending Objects') {
		        go('#allstate', bootdest + '/provision?allstate=1&liststate=' + liststate + '&object=' + active, '#allstate', unavailable, true, false, true);
                last_data = data;
                poll(30, check_pending, 'pendingcount');
		    } else {
                last_data = data;
                poll(30, check_pending, 'pendingcount');
            }
            if(debug)
                $('#pendingcount2').html('result: ' + data);
        } else {
            last_data = data;
            $('#pendingtest').html(last_data);
            if(debug)
                $('#pendingcount2').html('result: new pending data');
            poll(3, check_pending, 'pendingcount');
        }
}
function check_pending() {
    if(first_time) {
        first_time = false;
        go('#pendingtest', bootdest + '/provision?force=1&pending=1&object=' + active, '#pendingresult', unavailable, true, pending_callback, false);
    } else {
        go('#pendingtest', bootdest + '/provision?pending=1&object=' + active, '#pendingresult', unavailable, true, pending_callback, false);
        go('#allstate', bootdest + '/provision?allstate=1&liststate=' + liststate + '&object=' + active, '#allstate', unavailable, true, false, true);
    }
}
function checkMonitor() {
	var error = "CloudBench is unreachable, will try again later...";
	$('#count').html("Polling...");
	go('#monitordata', bootdest + '/monitordata', '', error, false, resetMonitor, false);
}    

function make_child(node) {
     var contents = "<" + node.nodeName;
    for(var y = 0; y < node.attributes.length; y++) {
        contents += " " + node.attributes[y].name + "='" + node.attributes[y].value + "'";
    }
     if (node.childElementCount == 0)
         contents += "/";
     contents += ">\\n";
     for(var x = 0; x < node.childElementCount; x++)
         contents += make_child(node.childNodes[x]);
     if (node.childElementCount > 0)
         contents += "</" + node.nodeName + ">\\n";
    return contents;
}

  /* Used in click events. We want to know if the parent of a click event
     object is the body itself or an internal div. This allows us to
     make sure we don't hide the content when we click on the content itself.
     */
  function findParentNode(parentName, childObj, stopName) {
	    var testObj = childObj.parentNode;
	    var count = 1;
	    if("getAttribute" in testObj) {
		    while(testObj.getAttribute('id') != parentName && testObj.getAttribute('id') != stopName) {
	//	        alert('My id  is ' + testObj.getAttribute('id') + '. Let\'s try moving up one level to see what we get.');
			testObj = testObj.parentNode;
			count++;
		    }
	    } else {
		return false;
	    }
	    // now you have the object you are looking for - do something with it
//	    alert('Finally found ' + testObj.getAttribute('id') + ' after going up ' + count + ' level(s) through the DOM tree');
	    return (testObj.getAttribute('id') == stopName) ? false : true;
  }

  var last_opened = "";

  function toggle_specific(prefix, name, check) {
        var elms = document.getElementsByClassName(prefix + name);

        if (check) {
            if(elms[0].style.display == 'none') {
               if (last_opened != "" && last_opened != name) {
                   toggle(last_opened, 0);
               }
               last_opened = name;
            } else {
               last_opened = "";
            }
        }

        for (var i = 0; i < elms.length; i++) {
            e = elms[i];

            if(e.style.display == 'none') {
                   e.style.display = 'block';
            } else {
                   e.style.display = 'none';
            }
        }
  }
  function toggle(name, check) {
           toggle_specific('trans', name, check);
           toggle_specific('blank', name, 0);
  }

  function process_edits(uuid, operation) {
      var tids = [];
      var nbunits = [];
      var chars = [];
      var pinyin = [];
      var indexes = [];

      $("span.label > a").each(function(index) {
        chars.push($(this).text());
        tids.push($(this).attr('uniqueid'));
        nbunits.push($(this).attr('nbunit'));
        pinyin.push($(this).attr('pinyin'));
        indexes.push($(this).attr('index'));
      });

      var out = "";
      if (chars.length == 0) {
          out += "You have not selected anything!";
      } else if (operation == "split" && chars.length > 1) {
          out += "You cannot split more than one word at a time!";
      } else if (operation == "split" && chars[0].split('').length < 2) {
          out += "This word only has one character. It cannot be split!";
      } else if (operation == "merge" && chars.length < 2) {
          out += "You need at least two characters selected before you can merge them into a word!";
      } else {
          out += "<h4>Are you sure you want to <b>";
          out += (operation == "split" ? "Split" : "Merge");
          out += "</b> these words ";
          out += (operation == "split" ? "APART" : "TOGETHER");
          out += "?</h4>";
          button = "<a class='btn btn-success' href='" + bootdest;
          button += "/edit?operation=" + operation + "&uuid=" + uuid + "&units=" + chars.length;
          var consecutive = true;

          if (operation == "split") {
              out += "<div style='font-size: 200%'>" + chars[0] + " (" + pinyin[0] + ")<br/></div>";
              button += "&nbunit=" + nbunits[0];
              button += "&tid=" + tids[0];
              button += "&index=" + indexes[0];
          } else {
              out += "<table>";
              for(var x = 0; x < chars.length; x++) {
                 if (x > 0 && ((parseInt(nbunits[x]) - 1) != parseInt(nbunits[x-1]))) {
                     consecutive = false; 
                     break;
                 }
                 if (!consecutive) {
                        break;
                 }
                 out += "<tr><td style='font-size: 200%'>" + chars[x] + "</td><td style='font-size: 200%'>&nbsp;" + pinyin[x] + "</td></tr>";
                 out += "<tr><td>&nbsp;</td></tr>";
                 button += "&nbunit" + x + "=" + nbunits[x];
                 button += "&tid" + x + "=" + tids[x];
                 button += "&index" + x + "=" + indexes[x];
              }
              out += "</table>";
          }
          if (consecutive) {
              button += "'>" + (operation == "split" ? "Split" : "Merge")+ "!</a>";
              out += "<p/><p/>" + button;
          } else {
              out = "The selected characters are not consecutive (including punctuation). You cannot merge them.";
          }
      }

      $('#regroupdestination').html(out);
      $('#regroupModal').modal('show');
  }

  function process_instant() {
      var chars = [];
      var allchars = "";
      $("span.label > a").each(function(index) {
        var split = $(this).text().split('');
        for(var x = 0; x < split.length; x++) {
            chars.push(split[x]);
        }
      });

      for(var x = 0; x < chars.length; x++) {
          allchars += chars[x];
      }
        
      if (allchars == "") {
          alert("You have not selected anything!");
      } else {
       $('#instantspin').attr('style', 'display: inline');
       $('#instantdestination').html("");
       go('#instantdestination', 
          bootdest + '/read?human=1&instant=' + allchars, 
          '#instantresult', 
          unavailable, 
          true, 
          offinstantspin,
          true);
       }
  }

  function select_toggle(name) {
       var spanclass = $("#spanselect_" + name).attr('class');
       if (spanclass == "none") {
           $("#spanselect_" + name).attr('class', 'label label-info');
       } else {
           $("#spanselect_" + name).attr('class', 'none');
       }
  }

  function change(id, url, getSpecificContent, error, writeSubcontent, callback, write, opaque1, opaque2) {
      jQuery.support.cors = true;
      jQuery.ajax({
        url: url,
        type: "GET",
        dataType: "html",
        error: function (XMLHttpRequest, ajaxOptions, thrownError) {
              if(XMLHttpRequest.statusText == 'error') {
                  $(id).html(error);
              }
             if(callback != false) {
               callback('error');
             }
        },
        success: function (response) {
            var data = "none";
            if(response.indexOf("<h4>Exception:</h4>") != -1 && response.indexOf("<h4>") != -1) {
                $(id).html(response);
            } else {
	            if(getSpecificContent != '') {
	                data = $(response).find(getSpecificContent).html();
	                if(write) {
	                    if(writeSubcontent)
	                        $(id).html(data);
	                    else
	                        $(id).html(response);
	                }
	            } else {
	                if(write)
	                    $(id).html(response);
	                data = response;
	            }
	            if(callback != false)
	               callback(data, opaque1, opaque2);
            }
        }
      });
  }

function multipopinstall(trans_id, unused) {
    $('#ttip' + trans_id).popover({placement: 'bottom-right',
                                   trigger: 'click',
                                   html: true,
                                   content: function() {
                                        return $('#pop' + trans_id).html();
                                   }});
}

function multipoprefresh(data, trans_id, spy) {
    $('#ttip' + trans_id).html(spy);
    $('#ttip' + trans_id).popover('hide');
}

function multiselect(uuid, index, nb_unit, trans_id, spy) {
          change('#pop' + trans_id, 
          bootdest + '/home?view=1&uuid=' + uuid + '&multiple_select=1'
          + '&index=' + index + '&nb_unit=' + nb_unit + '&trans_id=' + trans_id, 
          '#multiresult', 
          unavailable, 
          true, 
          multipoprefresh,
          true,
          trans_id,
          spy);
}

function memolist(uuid) {
   go('#memolist', 
          bootdest + '/read?uuid=' + uuid + '&memolist=1', 
          '#memolistresult', 
          unavailable, 
          true, 
          false,
          true);
}

function editslist(uuid) {
   go('#editslist', 
          bootdest + '/edit?uuid=' + uuid + '&editslist=1', 
          '#editsresult', 
          unavailable, 
          true, 
          false,
          true);
}

function history(uuid) {
   go('#history', 
          bootdest + '/read?uuid=' + uuid + '&phistory=1', 
          '#historyresult', 
          unavailable, 
          true, 
          false,
          true);
}

function memory_finish(data, opaque1, opaque2) {
    var hash = opaque1;
    var uuid = opaque2;
//    memolist(uuid);
//    history(uuid);
    toggle(hash, 0);
    toggle_specific('memory', hash, 0);
}

function memory(id, uuid, nb_unit, memorized) {
   toggle_specific('memory', id, 0);
   change('#memory' + id, 
          bootdest + '/read?uuid=' + uuid + '&memorized=' + memorized + '&nb_unit=' + nb_unit, 
          '#memoryresult', 
          unavailable, 
          true, 
          memory_finish,
          false,
          id,
          uuid);
}

function memorize(id, uuid, nb_unit) {
    memory(id, uuid, nb_unit, 1);
}

function forget(id, uuid, nb_unit) {
    memory(id, uuid, nb_unit, 0);
}


$.browser.device = (/android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i.test(navigator.userAgent.toLowerCase()));

if ($.browser.device == true) {
    modifyStyleRuleValue("width", "#main-nav:target", "50%");
    modifyStyleRuleValue("width", "#main-nav:target + .page-wrap", "50%");
} else {
    modifyStyleRuleValue("width", "#main-nav:target", "30%");
    modifyStyleRuleValue("width", "#main-nav:target + .page-wrap", "70%");
}

function togglecanvas() {
      if ($('#offnav').attr('href') == '#main-nav') {
        $('#offnav').attr('href', '#');
      } else {
        $('#offnav').attr('href', '#main-nav');
      }
}

function offinstantspin(data) {
    $('#instantspin').attr('style', 'display: none');
    $('#instantModal').modal('show');
//    $(document).unbind("mouseup");
//    $(document).unbind("mouseleave");
//    $(document).unbind("copy");
//    install_highlight();
}

function install_highlight() {

    if(!window.Kolich){
      Kolich = {};
    }

    Kolich.Selector = {};
    Kolich.Selector.getSelected = function(){
      var t = '';
      if(window.getSelection){
        t = window.getSelection();
      }else if(document.getSelection){
        t = document.getSelection();
      }else if(document.selection){
        t = document.selection.createRange().text;
      }
      return t;
    }

    Kolich.Selector.mouseup = function(){
      var st = Kolich.Selector.getSelected();
      if(st != '') {
           $('#instantspin').attr('style', 'display: inline');
           $('#instantdestination').html("");
           go('#instantdestination', 
              bootdest + '/read?human=1&instant=' + st, 
              '#instantresult', 
              unavailable, 
              true, 
              offinstantspin,
              true);
      }
    }

    Kolich.Selector.mouseleave = Kolich.Selector.mouseup;
    Kolich.Selector.copy = Kolich.Selector.mouseup;

    $(document).ready(function(){
      $(document).bind("mouseup", Kolich.Selector.mouseup);
      $(document).bind("mouseleave", Kolich.Selector.mouseleave);
      $(document).bind("copy", Kolich.Selector.mousecopy);
    });
}

function modifyStyleRuleValue(style, selector, newstyle, sheet) {
    var sheets = typeof sheet !== 'undefined' ? [sheet] : document.styleSheets;
    for (var i = 0, l = sheets.length; i < l; i++) {
        var sheet = sheets[i];
        var all = "";
        var rules = sheet.cssRules;
        if (!rules) {
            rules = sheet.rules;
        }
        if( !rules ) { 
            continue; 
        }
        for (var j = 0, k = rules.length; j < k; j++) {
            var rule = rules[j];
            all += rule.selectorText + "\n";
            if (rule.selectorText && rule.selectorText.split(',').indexOf(selector) !== -1) {
//                alert("Old: " + rule.style[style])
                rule.style[style] = newstyle;
            }
        }
    }
}

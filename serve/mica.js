  debugger;
var last_data = '';
var first_time = true;
var debug = false;
//var debug = true;
var unavailable = "error!";
var prmstr = window.location.search.substr(1);
var prmarr = prmstr.split ("&");
var params = {};
var heromsg = "<div class='hero-unit' style='padding: 5px'>";
var translist = [];
for ( var i = 0; i < prmarr.length; i++) {
    var tmparr = prmarr[i].split("=");
    params[tmparr[0]] = tmparr[1];
}
var active = "app";
var liststate = "all";

var spinner = "<img src='data:image/gif;base64,R0lGODlhEAAQAPeuAPv7++/v7/z8/Pb29vr6+ubm5vf39+3t7fn5+eTk5P7+/vj4+PT09PLy8t7e3tjY2PPz8+zs7PX19YuLi+Hh4evr66+vr7q6utTU1HV1da6uroGBgZycnOXl5ampqZ+fn3Jycv39/ejo6NPT06Ojo+np6WZmZrCwsLe3t+Dg4OLi4n9/f8LCwtfX17u7u7y8vJeXl9/f38HBwczMzMnJycjIyMrKylpaWu7u7sPDw6WlpZmZmfHx8dDQ0NHR0WdnZ5ubm+rq6qenp9nZ2Xh4eM3NzcDAwHx8fD8/P1RUVEJCQmpqaqysrOPj4yQkJNLS0vDw8I2NjY+Pj9vb27S0tOfn54WFhZKSkp2dnQYGBtra2s/Pz2xsbH19fXt7e6qqqsbGxrm5uYqKinp6epCQkIiIiLW1tTAwML6+vlZWVioqKmRkZE5OTsTExBcXF6GhoS4uLkdHR5GRkVhYWDU1NWhoaMXFxc7Oztzc3CwsLIODg15eXpOTk1tbW7KyshoaGpWVlWNjY5iYmNbW1t3d3ScnJ9XV1W9vb2tra8fHx35+fkBAQEpKSlJSUjs7O4aGhkxMTJSUlC0tLUtLS7GxsTg4OG1tbW5ubqCgoF1dXYSEhLOzs6urq8vLy46Ojq2trZ6ennd3d7a2toyMjDw8PLi4uEVFRXFxcWBgYImJiXZ2dqioqDIyMlFRUf///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQFCgCuACwAAAAAEAAQAAAIvQBdCRzoyosXgghd2ajEwNWNG64UdFiQkIEkPQ4hBkiggCAeAq6Y/HHwEACFARFRulISx4WrSSA+fDggwlWAESMEQtmQZ0+FEgIFABhSpIkAj5pqDiSgwsDADxOiukRYAINVLViiTiiVsOrVgVVmEjQwo8FYHWlC4eAhcMCACzpmgHR1yQQLV3xA9eiBxoMrFRpOCNTi9EkdFR48BLjSwpUAHAQBHNHhKrGrNkCOIiREpKFlAliqJCRoxszogAAh+QQFCgCuACwAAAAAEAAQAAAIwQBdCRzoyooVgghdbWEkwdWPH64gFAKTUMIiTw4hEnGCgGAMgZvgUHg4JQsVgQQEJpkjw1WfFUKEcEHiSkKCDgJ5REFi6UAFgUEaiKCAQ4HHKAcICjiQUiATGFApIjyQomoBElBhoElItSpOgSW+BCCI4EHDgQO+LCkDoYFAAwsSXXgAQOARIjRcveHUooWNMK4KGGEhMEbKB0cKoEDRQIcKgW4HCohCydViV3dOhEhIQcwAyyhcAbCQNOFAGS0TBgQAIfkEBQoArgAsAAAAABAAEAAACMIAXQkc6IoMGYIIXWHoM8BVhgyucJyxkXBAI0EOIWagg7AJAFculCR46MDNBVcIngg0sWSGK0RSNGggksSVBidqBELYkUQPjgACI5RAkgUEBIJNYAAdmIDLg4EnSEilkRBChKtQmEglkajq1QhLXUUww4AgABULCBow00WQhIYoEQwp0kSAwAlierg6gSZGjEGdXAV4MkJgAoEOrgTIkUPChSCuQkhA+KGNK8auhrBI6KrABwKXc7gSYIQH54EzXCYMCAAh+QQFCgCuACwAAAAAEAAQAAAIvwBdCRzoCggQgghdPeBiwNWGDa6gKNmS0MAaEg4hbohDgGABgSzSVHlIIY8RVwZ6CBxz5IkrL0BcuDgSyJWfM44EDvBQR44rHgIrdGDzxwoDjzqADiwwxsHACxaiqkT4wYTVDVClJqxqVdHAADIGEBRwAADBBTKurBrQ0BUAACIoBFDgSgEHDi1chbFRoIAKLa4kJOggsIRZFToa+PCxoAiUuh0Hhjhxx9ViVwlG0EUY5ITZyyGeSEhI8MED0gEBACH5BAUKAK4ALAAAAAAQABAAAAi6AF0JHOjqjQaCCF0R6rLAlZQdrngkwZAQAJGDD11FmYNQhABXNJaUeJgACRiBFF1NiPLAlRghL8CUOeUqjBJIAg1QOYIJSgOBB1ztgUNGAsESlH4OFPGIwkA7L6K2SCgEhNUJUKVStQqizMAGMwwQTHBoCkECM3RcWIBAoIAGSLJkgCDQggYVIAcd2CvClQYnagTi+FjgggQHDgBQGOAKgSGERoa4QuwqQIKElVl8pKwgQUPMAjt0wBwQACH5BAUKAK4ALAAAAAAQABAAAAi9AF0JHOiKCROCCF1RiILAFQcOriCsSZFQgJgwDiHuWAKAYImOPbpEeOggyQxXC7QIxPJhiqsdfmjQAGTFlYskmQQukHHFAgMGAgNAQaQEyACCAYwAHRhEToKBW2pIjZFQw4qrgKJOrXp1BZ+BDFo0HFhgzAOCAB5csIGgo6sgJdi46cJDoAwWIlw9oAABAhclrqjQYSWwQQhXAYosqFBhShYqAs8OVDDiKWNXRJyMJchgxOHLEJw8SYg0AOmAACH5BAUKAK4ALAAAAAAQABAAAAi9AF0JHOgKBQqCCF1V+UDAlQcPrhgQSZDQFYc2DiEyOYLwgABXLa4EeFhiyRNXCBwIPHFChUM0PXoI4eOKhYlLAgnM0HFhwACBDXh4SaPDAMEGM34OPIClykAtGKIWSOhigtUPUKVStToBy0ADKhoOFKEJD0EBTYoMAfDRVYkKe/KkaiBwxIgArkQc+PABxCRXLuKYEjhAgasBFADcuOHgDxNXBMwSTIB3sSs9khgkXNDBsGUGlWxUHOjFS8WAACH5BAUKAK4ALAAAAAAQABAAAAjDAF0JHOiKBQuCCF0FOQHAFQoUrgaIKZAwxIk7DiGiiCKAIA+BKnQ0eBihywNXBFIIZGFEhKswNlq08PPGVREiRwQCeHDBxgIDAhlAGLXkywCCEloAHcjjS4mBBVJIPZDQCIyrJDpITUEVIZirMJgMBHCg48ADUmIQVICDgogGVQRWOGAJSSQGAjskkOAKSSAhQlb0cSVjThqBBARSyTLlxw8KcDYJVDsQgRMirhy78rSIr9dCEDL/cCWB0ZaEBK1YQR0QACH5BAUKAK4ALAAAAAAQABAAAAi9AF0JHOiqSBGCCF0FYCHAVY4crghgSSiQxRCHENt8QCghhKsgFyQ8DHDFgcACAkeMCODKBoYYMdCccDVCzASBApoUGYJggcABDIB0MWOA4AIVBAgyoBJhIJQIUCEkpEGi6okAUCNIRUjV6sApXBIQDACkCUEIGbIgKVFCIFY9SXZIEKjGiQZXrQ5p0CAFkasZS+oINITA1QU3rjJkSKDEhSsAZgnSyZCYsqBGAxLaOIOjsqsBfTBQHEiGDMWAACH5BAUKAK4ALAAAAAAQABAAAAjBAF0JHOhqyBCCCF0xGBHClQ8frgBYCJJQwYgEDiHeOdFwIAEFrqAUWfCwgQ4VESm66pBAQsEUBQrYCONKCwcOIBUEoCACAAGBBgZwuiJjAUEABwQQHGAkwMANJqJ+SNjDgtULiqKamIqw6tWBDsYUINjAw9iBDKz8YaOigkAeOOTU+TJAoKMzFlyhOuLCBRAvrp4cGSNwhAFXRvI42LChShoWAs8KJBBngyvGrkisOYxwixIoly0b4PIgIUEgQEwHBAAh+QQFCgCuACwAAAAAEAAQAAAIvwBdCRzoqkMHgghdLeigwJUDB64EyAiQ0FUCig9dDTGC8AkCVwMoAHgo4UKBiDgEqnGiwVWVCAcODKLhSsUJCwIhgMiCpIEAgQgWXNAxgwDBB1wSEDTQqcHACSCiCknY4oVVO2WigpiKsOrVgRQeiSDIgEoJghLIwNnT4YDABg0wHTFjQCAkJaJcHSpTw4gQMa4eRJkgsIVAMEgo7JBSYglNAWMJzoniarErDaoAJMSQhEdlKQrHEKo4kMmbigEBACH5BAUKAK4ALAAAAAAQABAAAAi8AF0JHOgqQACCCF3RKATBVYUKrkKMYJAQgRMiDiEmGKGA4AOBVLJMebigyMEQDQSeoUPFFalAECBQ+CiChQyBODK4YVOiikAACGxceAAAIZECBBcYaigQ0IqnGhLGqEF1C5+nK6IinFp1YIJIQQgOkHFw4AAgSkxEKMuAwacrMhYIzJTEhSsrcmjQ8LPD1RQsWAQ+GOBqRhIHHDhE6NLDFYCwAwEs6ZvYVZgyAhI+WNOwMoIJTRIS/PJFdEAAOw==' width='20px'>";

if ("object" in params)
    active = params["object"];
    
if ("liststate" in params)
    liststate = params["liststate"];

  var do_refresh = false;
  var secs = 20;
  var failcount = 0;
  var newRefresh = 0;
  var finish = false;

function local(msgid) {
    return $("#" + msgid).html();
}
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
               callback(error);
        },
        success: function (response) {
            var data = "none";
            if(response.indexOf(local("notsynchronized")) != -1 || (response.indexOf("<h4>Exception:</h4>") != -1 && response.indexOf("<h4>") != -1)) {
                $(id).html(response);
            } else {
	            if(getSpecificContent != '') {
                    obj = $(response)
                    objresult = obj.find(getSpecificContent)
	                data = objresult.html();
	                if(write) {
	                    if(writeSubcontent) {
	                        $(id).html(data);
	                    } else
	                        $(id).html(response);
	                }
	            } else {
	                if(write)
	                    $(id).html(response);
	                data = response;
	            }

                if(write) {
                        //have to replace script or else jQuery will remove them
                        $(response.replace(/script/gi, 'mikescript')).find(getSpecificContent).find('mikescript').each(function (index, domEle) {
                            if (!$(this).attr('src')) {
                                eval($(this).text());
                            }
                        });
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
    var page = parseInt(tmparr[2]) + 1;
    var pages = parseInt(tmparr[3]); 
    
    if (pages == 0) {
    	pages = page;
    }

    if (result == "yes" || first_time) {
        $("#translationstatus" + uuid).html(spinner + "&nbsp;&nbsp;" + local("working") + ": " + local("page") + ": " + page + "/" + pages + ", " + percent + "%");
        trans_wait_poll(uuid);
    } else {
        $("#translationstatus" + uuid).html(local('donereload'));
        loadstories(false);
    }
}

function trans_poll(uuid) {
   change('',
       '/home?tstatus=1&uuid=' + uuid, 
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
    loadstories(false);
}

function trans_start(uuid) {
    $("#transbutton" + uuid).attr("style", "display: none");
    do_refresh = true;
    first_time = true;
    finish = trans_poll;
    trans_poll(uuid);
    $("#translationstatus").html(spinner + "&nbsp;" + local("storiestranslating") + "...");
    $("#translationstatus" + uuid).html(spinner + "&nbsp;" + local("translating") + "...");
}

function trans(uuid) {
   trans_start(uuid);
   change('#translationstatus', 
       '/home?translate=1&uuid=' + uuid, 
       '#translationstatusresult', 
       unavailable, 
       true, 
       trans_stop,
       true,
       uuid,
       false);
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
//		        alert('My id  is ' + testObj.getAttribute('id') + '. Let\'s try moving up one level to see what we get.');
			testObj = testObj.parentNode;
			count++;
		    }
	    } else {
		return false;
	    }
	    // now you have the object you are looking for - do something with it
//	    alert('Finally found **' + testObj.getAttribute('id') + ' after going up ' + count + ' level(s) through the DOM tree');
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

      
  function prepare_one_edit(batch, uuid, tids, transids, nbunits, chars, pinyin, indexes, pages, operation) {
  	  var op = { 
  	  			"operation": operation,
  	  			"uuid" : uuid,
  	  			"units" : chars.length,
  	  			"failed" : true,
  	  			"chars" : chars[0],
  	  			"pinyin" : pinyin[0]
  	  			 };
      var out = "";
      if (chars.length == 0) {
          out += local("notselected");
      } else if (operation == "split" && chars.length > 1) {
          out += local("cannotsplit");
      } else if (operation == "split" && chars[0].split('').length < 2) {
          out += local("onlyhasone");
      } else if (operation == "merge" && chars.length < 2) {
      	  if (batch)
      	      return "";
          out += local("atleasttwo");

      } else {
          var consecutive = true;

          if (operation == "split") {
              op["nbunit"] = nbunits[0];
              op["tid"] = tids[0];
              op["index"] = indexes[0];
              op["pagenum"] = pages[0];
              op["pinyin"] = pinyin[0];
          } else {
              for(var x = 0; x < chars.length; x++) {
                 if (x > 0 && ((parseInt(transids[x]) - 1) != parseInt(transids[x-1]))) {
                     consecutive = false; 
                     break;
                 }
                 if (!consecutive) {
                        break;
                 }
                 op["nbunit" + x] = nbunits[x];
                 op["tid" + x] = tids[x];
                 op["index" + x] = indexes[x];
                 op["page" + x] = pages[x];
	             op["chars" + x] = chars[x];
	             op["pinyin" + x] = pinyin[x];
              }
          }
          if (consecutive) {
	      	  op["failed"] = false;
          } else {
              out = local("notconsecutive");
          }
      }
      
      op["out"] = out
      
      return op;
  }
  
  function process_edits(uuid, operation, batch) {
      var tids = [];
      var transids = [];
      var nbunits = [];
      var chars = [];
      var pinyin = [];
      var indexes = [];
      var pages = [];
      var batchids = [];
      var operations = [];
      var selector_class = batch ? "batch" : "label";
      var edits = []

      $("span." + selector_class + " > a").each(function(index) {
        chars.push($(this).text());
        tids.push($(this).attr('uniqueid'));
        nbunits.push($(this).attr('nbunit'));
        transids.push($(this).attr('transid'));
        pinyin.push($(this).attr('pinyin'));
        indexes.push($(this).attr('index'));
        pages.push($(this).attr('page'));
        batchids.push($(this).attr('batchid'));
        operations.push($(this).attr('operation'));
      });
      
      var out = "";
      
      if (batch) {
			var t_tids = [];
			var t_transids = [];
			var t_nbunits = [];
			var t_chars = [];
			var t_pinyin = [];
			var t_indexes = [];
			var t_pages = [];
			var t_operations = [];
			var curr_batch = batchids[0];
		    for (var x = 0; x < batchids.length; x++) {
		    	if (batchids[x] != curr_batch) {
					edits.push(prepare_one_edit(batch, uuid, t_tids, t_transids, t_nbunits, t_chars, t_pinyin, t_indexes, t_pages, t_operations[0]));
					t_tids = [];
					t_transids = [];
					t_nbunits = [];
					t_chars = [];
					t_pinyin = [];
					t_indexes = [];
					t_pages = [];
					t_operations = [];
				}
				
				curr_batch = batchids[x];
			
	    		t_tids.push(tids[x]);
	    		t_transids.push(transids[x]);
	    		t_nbunits.push(nbunits[x]);
	    		t_chars.push(chars[x]);
	    		t_pinyin.push(pinyin[x]);
	    		t_indexes.push(indexes[x]);
	    		t_pages.push(pages[x]);
	    		t_operations.push(operations[x]);
		    }
		    
		    // handle the last batch...
		    
		    if (t_tids.length > 0) {
				edits.push(prepare_one_edit(batch, uuid, t_tids, t_transids, t_nbunits, t_chars, t_pinyin, t_indexes, t_pages, t_operations[0]));
		    }
      } else {
		  edits.push(prepare_one_edit(batch, uuid, tids, transids, nbunits, chars, pinyin, indexes, pages, operation));
      }
      
      out += "<h4>" + local("areyousure") + "</h4>\n";
      out += "<form method='post' action='/edit'>"
      var editcount = 1;
      out += "<table>"
      for(var x = 0; x < edits.length; x++) {
	      out += "<tr>";
      	  out += "<td>#" + editcount + ")&nbsp;</td>";
      	  	
      	  if (edits[x]["operation"] == "split") {
      	  	  out += "<td>" + local("split") + " "; 
	      	  if (edits[x]["failed"] == true) {
		      	  out += "(INVALID)"
	      	  } else {
		      	  editcount += 1;
	      	  }
	      	  out += ":&nbsp;</td><td>" + edits[x]["chars"] + "(" + edits[x]["pinyin"] + ")</td>";
	      } else {
      	  	  out += "<td>" + local("merge") + " "; 
	      	  if (edits[x]["failed"] == true) {
		      	  out += "(" + local("invalid") + ")"
	      	  } else {
		      	  editcount += 1;
	      	  }
	      	  
			  out += ":&nbsp;</td>";
	      	  for (var y = 0; y < edits[x]["units"]; y++) {
	      	  	  if (edits[x]["chars" + y] == undefined)
			          out += "<td>" + edits[x]["chars"] + "</td>"
			      else 
			          out += "<td>" + edits[x]["chars" + y] + "</td>"
			          
	      	  	  if (edits[x]["pinyin" + y] == undefined)
			          out += "<td>&nbsp;" + edits[x]["pinyin"];
			      else
			          out += "<td>&nbsp;" + edits[x]["pinyin" + y];
	      	  	  if (y < (edits[x]["units"] - 1)) {
	      	  	      out += ", &nbsp;";
	      	  	  }
				  out += "</td>";
	      	  }
      	  }
	      out += "</tr>";
      	  if (edits[x]["failed"] == true) {
      	  	out += "<tr><td></td><td>" + local("reason") + ":</td><td colspan='100'>" + edits[x]["out"] + "</td></tr>";
      	  }
      }
      out += "</table>"
  	  out += "<input type='hidden' name='oprequest' value='" + JSON.stringify(edits) + "'/>\n";
  	  out += "<input type='hidden' name='uuid' value='" + uuid + "'/>\n";
  	  out += "<p/><p/>";
  	  if (editcount > 1) {
	      out += "<input class='btn btn-default btn-primary' name='submit' type='submit' value='" + local("submit") + "'/>";
	  } else {
	      out += local("seeabove");
  	  	
  	  }
      out += "</form>"

      $('#regroupdestination').html(out);
      $('#regroupModal').modal('show');
  }

  function process_instant(with_spaces, lang, source, target, username, password) {

      var chars = [];
      var allchars = "";
      $("span.label > a").each(function(index) {
	      if (with_spaces) {
		chars.push($(this).text());
	      } else {
		var split = $(this).text().split('');

		for(var x = 0; x < split.length; x++) {
		    chars.push(split[x]);
		}
	      }
      });

      for(var x = 0; x < chars.length; x++) {
          allchars += chars[x];
	  if (with_spaces) {
	      if (x != (chars.length - 1))
                  allchars += " ";
	  }
      }
        
      if (allchars == "") {
          alert(local("notselected"));
      } else {
       $('#instantspin').attr('style', 'display: inline');
       $('#instantdestination').html("");

       var url = '/instant?source=' + allchars + "&lang=" + lang + "&source_language=" + source + "&target_language=" + target

       if (username)
           url += "&username=" + username
       if (password)
           url += "&password=" + password

       change('#instantdestination', url,
          '#instantresult', 
          local("onlineoffline"),
          true, 
          offinstantspin,
          true,
          $("html").scrollTop(),
          false);
       }
  }

  function select_toggle(name) {
       var spanclass = $("#spanselect_" + name).attr('class');
       if (spanclass == "none") {
           $("#spanselect_" + name).attr('class', 'label label-info none');
       } else if (spanclass == "batch") {
           $("#spanselect_" + name).attr('class', 'label label-info batch');
       } else if (spanclass == "label label-info batch") {
           $("#spanselect_" + name).attr('class', 'batch');
       } else if (spanclass == "label label-info none") {
           $("#spanselect_" + name).attr('class', 'none');
       }
  }

  function change(id, url, getSpecificContent, error, writeSubcontent, callback, write, opaque1, opaque2) {
      var cb = callback;
      var o1 = opaque1;
      var o2 = opaque2;
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
               callback(error);
             }
        },
        success: function (response) {
            var data = "none";
            if(response.indexOf(local("notsynchronized")) != -1 || (response.indexOf("<h4>Exception:</h4>") != -1 && response.indexOf("<h4>") != -1)) {
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
                if(write) {
                        //have to replace script or else jQuery will remove them
                        $(response.replace(/script/gi, 'mikescript')).find(getSpecificContent).find('mikescript').each(function (index, domEle) {
                            if (!$(this).attr('src')) {
                                eval($(this).text());
                            }
                        });
                }
	            if(cb != false && cb != undefined)
	               cb(data, o1, o2);
            }
        }
      });
  }

function multipopinstall(trans_id, unused) {
    $('#ttip' + trans_id).popover({placement: 'bottom',
//    $('#ttip' + trans_id).popover({placement: 'bottom-right',
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

function multiselect(uuid, index, nb_unit, trans_id, spy, page) {
          change('#pop' + trans_id, 
          '/home?view=1&uuid=' + uuid + '&multiple_select=1'
          + '&index=' + index + '&nb_unit=' + nb_unit + '&trans_id=' + trans_id + "&page=" + page, 
          '#multiresult', 
          unavailable, 
          true, 
          multipoprefresh,
          true,
          trans_id,
          spy);
}

function process_reviews(uuid, batch) {
      var count = 0;
      var out = "";
      var form = "";
      form += "<form method='post' action='/home'>"
      out += "<ol>";

      $("span.review").each(function(index) {

        out += "<li>(" + $(this).attr('source') + ") " + local("reviewchange") + ": " + $(this).attr('target') + "</li>";
        form += "<input type='hidden' name='transid" + count + "' value='" + $(this).attr('transid') + "'/>\n";
        form += "<input type='hidden' name='index" + count + "' value='" + $(this).attr('index') + "'/>\n";
        form += "<input type='hidden' name='nbunit" + count + "' value='" + $(this).attr('nbunit') + "'/>\n";
        form += "<input type='hidden' name='page" + count + "' value='" + $(this).attr('page') + "'/>\n";
        //form += "<input type='hidden' name='target" + count + "' value='" + $(this).attr('target') + "'/>\n";
        //form += "<input type='hidden' name='source" + count + "' value='" + $(this).attr('source') + "'/>\n";

        count += 1;
      });

      out += "</ol>";
      form += "<input type='hidden' name='count' value='" + count + "'/>\n";
      
      form += "<input class='btn btn-default btn-primary' name='bulkreview' type='submit' value='" + local("submit") + "'/>";
      form += "</form>"
      out += form

      if (count == 0) {
          out = "<h4>" + local('norecommend') + "</h4>";
      }
      $('#reviewdestination').html(out);
      $('#reviewModal').modal('show');
}

var view_images = false;
var show_both = false;
var current_meaning_mode = false;
var current_view_mode = "text";
var current_page = -1;
var current_mode = "read";
var current_uuid = "uuid";
var curr_img_num = 0;
var curr_pages = 0;

function change_pageimg_width() {
    $('#pageimg' + curr_img_num).css('width', $('#pageimg' + curr_img_num).width());
    $('#pageimg' + curr_img_num).css('top', 55 + $('#readingheader').height());
    $('#pageimg' + curr_img_num).css('bottom', 0);
}

function restore_pageimg_width() {
    $('#pageimg' + curr_img_num).css('width', '100%');
}

function finish_new_account(code, who) {
    go('#newaccountresultdestination', 
        "/" + who + "?finish=1&code=" + code,
        '', 
        'error', 
        true,
        false, 
        true);
}

function view(mode, uuid, page) {
   $("#gotoval").val(page + 1);
   $("#pagetotal").html(current_pages);
   var url = '/' + mode + '?view=1&uuid=' + uuid + '&page=' + page;
   
   window.scrollTo(0, 0);
   if (show_both) {
       curr_img_num += 1;

       $("#pagecontent").html("<div class='col-md-5 nopadding'><div id='pageimg" + curr_img_num + "'>" + spinner + "&nbsp;" + local("loadingimage") + "...</div></div><div id='pagetext' class='col-md-7 nopadding'>" + spinner + "&nbsp;" + local("loadingtext") + "...</div>");
    
        $('#pageimg' + curr_img_num).affix();
        $('#pageimg' + curr_img_num).on('affix.bs.affix', change_pageimg_width); 
        $('#pageimg' + curr_img_num).on('affix-top.bs.affix', restore_pageimg_width); 
        $('#pageimg' + curr_img_num).on('affix-bottom.bs.affix', restore_pageimg_width); 

       go('#pagetext', 
              url, 
              '#pageresult', 
              unavailable, 
              true, 
	          false,
              true);

       url += "&image=0";

       go('#pageimg' + curr_img_num, 
              url, 
              '#pageresult', 
              unavailable, 
              true, 
	      false,
              true);
   } else {
       $("#pagecontent").html("<div class='col-md-12 nopadding'><div id='pagesingle'></div></div>");
       if (view_images) {
           url += "&image=0";
	       $("#pagesingle").html(spinner + "&nbsp;" + local("loadingimage") + "...");
       } else {
	       $("#pagesingle").html(spinner + "&nbsp;" + local("loadingtext") + "...");
       	
       }
       
       go('#pagesingle', 
              url, 
              '#pageresult',
              unavailable, 
              true, 
	      false,
              true);
   }

   listreload(mode, uuid, page);
   	   
   current_page = page;
   current_mode = mode;
   current_uuid = uuid;
}

function install_pages(mode, pages, uuid, start, view_mode, reload, meaning_mode) {
        current_pages = pages;
        current_view_mode = view_mode;
        current_meaning_mode = meaning_mode;
        if (view_mode == "text") {
             view_images = false;
	     show_both = false;
        } else if(view_mode == "images") {
             view_images = true;
	     show_both = false;
        } else if(view_mode == "both") {
             view_images = false;
	     show_both = true;
        }

        $('#pagenav').bootpag({
            total: pages,
                   page: start + 1,
                   maxVisible: 5 
        }).on('page', function(event, num){
          view(mode, uuid, num-1);
        });

	if(reload) {
            view(mode, uuid, start);
	}
}

function memory_finish(data, opaque1, opaque2) {
    var hash = opaque1;
    var uuid = opaque2;
    toggle(hash, 0);
    toggle_specific('memory', hash, 0);
}

function memory(id, uuid, nb_unit, memorized, page) {
   toggle_specific('memory', id, 0);
   change('#memory' + id, 
          '/read?uuid=' + uuid + '&memorized=' + memorized + '&nb_unit=' + nb_unit + '&page=' + page, 
          '#memoryresult', 
          unavailable, 
          true, 
          memory_finish,
          false,
          id,
          uuid);
}

function memorize(id, uuid, nb_unit, page) {
    memory(id, uuid, nb_unit, 1, page);
}

function forget(id, uuid, nb_unit, page) {
    memory(id, uuid, nb_unit, 0, page);
}

function reveal_all(hide) {
    //var curr = $("html").scrollTop(),
    var changed = {};
    $("div.reveal").each(
        function() { 
             var id = $(this).attr('revealid');
             if (changed[id] == undefined) {
                 changed[id] = true;
                 reveal(id, hide);
             }
        }
    );
    //$("html").scrollTop(curr);
}
function reveal(id, hide) {
   var rele = document.getElementsByClassName("reveal" + id);

   if (!hide) {
       if(rele[0].style.display != 'none') {
           toggle_specific('reveal', id, 0);
           toggle_specific('definition', id, 0);
       }
   } else {
       if(rele[0].style.display == 'none') {
           toggle_specific('reveal', id, 0);
           toggle_specific('definition', id, 0);
       }
   }
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
        loadstories(false);
      }
}

function offinstantspin(data, curr, unused) {
    //var data = JSON.parse(data);
    $('#instantdestination').html(data);
    $('#instantspin').attr('style', 'display: none');
    $('#instantModal').modal('show');
//    $(document).unbind("mouseup");
//    $(document).unbind("mouseleave");
//    $(document).unbind("copy");
//    install_highlight();
    $("html").scrollTop(curr);
}

function install_highlight() {

    if(!window.Trans){
      Trans = {};
    }

    Trans.Selector = {};
    Trans.Selector.getSelected = function(){
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

    Trans.Selector.mouseup = function(){
      var st = Trans.Selector.getSelected();
      if(st != '') {
           $('#instantspin').attr('style', 'display: inline');
           $('#instantdestination').html("");
           change('#instantdestination', 
              '/instant?source=' + st + "&lang=en", 
              '#instantresult', 
              unavailable, 
              false, 
              offinstantspin,
              false,
              $("html").scrollTop(),
              false);
      }
    }

    Trans.Selector.mouseleave = Trans.Selector.mouseup;
    Trans.Selector.copy = Trans.Selector.mouseup;

    $(document).ready(function(){
      $(document).bind("mouseup", Trans.Selector.mouseup);
      $(document).bind("mouseleave", Trans.Selector.mouseleave);
      $(document).bind("copy", Trans.Selector.mousecopy);
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

var list_mode = true;

function listreload(mode, uuid, page) {
       if (mode == "read") {
           if (list_mode)
               $("#memolist").html(spinner + "&nbsp;<h4>" + local("loadingstatistics") + "...</h4>");
           go('#memolist', 
              '/read?uuid=' + uuid + '&memolist=1&page=' + page, 
              '#memolistresult', 
              unavailable, 
              true, 
              false,
              true);
       } else if (mode == "edit") {
           if (list_mode)
               $("#editslist").html(spinner + "&nbsp;<h4>" + local("loadingstatistics") + "...</h4>");
           go('#editslist', 
                  '/edit?uuid=' + uuid + '&editslist=1&page=' + page, 
                  '#editsresult', 
                  unavailable, 
                  true, 
                  false,
                  true);
       } else if (mode == "home") {
           if (list_mode)
               $("#history").html(spinner + "&nbsp;<h4>" + local('loadingstatistics') + "...</h4>");
           go('#history', 
                  '/read?uuid=' + uuid + '&phistory=1&page=' + page, 
                  '#historyresult', 
                  unavailable, 
                  true, 
                  false,
                  true);
       }
}

function installreading() {
    $('#goto').click(function() {
        var page = parseInt($('#gotoval').val());
        if (page > current_pages) {
            page = current_pages;
        }

        page -= 1;
        install_pages(current_mode, current_pages, current_uuid, page, current_view_mode, true, current_meaning_mode);
    });
    $("#gotoval").keyup(function(event){
            if(event.keyCode == 13){ $("#goto").click(); }
    });
    $('#imageButton').click(function () {
        if($('#imageButton').attr('class') == 'active btn btn-default') {
           $('#imageButton').attr('class', 'btn btn-default');
           $('#textButton').attr('class', 'active btn btn-default');
           view_images = false;
	   go('#pagetext', '/home?switchmode=text', '', unavailable, false, false, false);
        } else {
           view_images = true; 
           $('#imageButton').attr('class', 'active btn btn-default');
           $('#textButton').attr('class', 'btn btn-default');
	       go('#pagetext', '/home?switchmode=images', '', unavailable, false, false, false);
        }
       show_both = false;
       $('#sideButton').attr('class', 'btn btn-default');
       current_view_mode = "images";
       view(current_mode, current_uuid, current_page);
       
    });
    $('#sideButton').click(function () {
        if($('#sideButton').attr('class') == 'active btn btn-default') {
           $('#sideButton').attr('class', 'btn btn-default');
           $('#textButton').attr('class', 'active btn btn-default');
           show_both = false;
	       go('#pagetext', '/home?switchmode=text', '', unavailable, false, false, false);
        } else {
           show_both = true; 
           $('#sideButton').attr('class', 'active btn btn-default');
           $('#textButton').attr('class', 'btn btn-default');
	       go('#pagetext', '/home?switchmode=both', '', unavailable, false, false, false);
        }
       current_view_mode = "both";
       view_images = false;
       $('#imageButton').attr('class', 'btn btn-default');
       view(current_mode, current_uuid, current_page);
    });
    
    $('#textButton').click(function () {
      go('#pagetext', '/home?switchmode=text', '', unavailable, false, false, false);
	   if (show_both == false && view_images == false) {
	   	  // already in text mode
	   	  return;
	   }
       $('#imageButton').attr('class', 'btn btn-default');
       $('#sideButton').attr('class', 'btn btn-default');
       $('#textButton').attr('class', 'active btn btn-default');
       current_view_mode = "text";
       show_both = false;
       view_images = false;
       view(current_mode, current_uuid, current_page);
    });

    $('#meaningButton').click(function () {
       if($('#meaningButton').attr('class') == 'active btn btn-default') {
           $('#meaningButton').attr('class', 'btn btn-default');
           current_meaning_mode = false;
           go('#pagetext', '/read?meaningmode=false', '', unavailable, false, false, false);
           reveal_all(true);
       } else {
           $('#meaningButton').attr('class', 'active btn btn-default');
           current_meaning_mode = true;
           go('#pagetext', '/read?meaningmode=true', '', unavailable, false, false, false);
           reveal_all(false);
       }
    });
}

function syncstory(name, uuid) {
    document.getElementById(name).innerHTML = local('requesting') + "...";
    go('#' + name, 
        '/storylist?uuid=' + uuid + "&sync=1",
        '', 
        'sync error', 
        false,
        function(unused) { 
         document.getElementById(name).innerHTML = local('started');
         document.getElementById(name).onclick = function() { unsyncstory(name, uuid); }; 
        },
        false);
}

function unsyncstory(name, uuid) {
    document.getElementById(name).innerHTML = local('stopping') + "...";
    go('#' + name, 
        '/storylist?uuid=' + uuid + "&sync=0",
        '', 
        'sync error', 
        false,
        function(unused) { 
         document.getElementById(name).innerHTML = local('stopped');
         document.getElementById(name).onclick = function() { syncstory(name, uuid); }; 
        },
        false);
}

function loadstories(unused) {

    $("#sidebarcontents").html("<p/><br/>" + spinner + "&nbsp;" + local("loadingstories") + "...");
    go('#sidebarcontents', 
    '/storylist',
    '#storylistresult', 
    unavailable, 
    true, 
    false,
    true);
}

function dropstory(uuid) {
    go('#sidebarcontents', 
    '/home?forget=1&uuid=' + uuid,
    '', 
    unavailable, 
    false, 
    loadstories,
    false);
}

function trashstory(uuid, name) {
    go('#sidebarcontents', 
    '/home?delete=1&uuid=' + uuid + "&name=" + name,
    '', 
    unavailable, 
    false, 
    loadstories,
    false);
}

function reviewstory(uuid, which) {
    go('#sidebarcontents', 
    '/home?reviewed=' + which + '&uuid=' + uuid,
    '', 
    unavailable, 
    false, 
    loadstories,
    false);
}

function finishstory(uuid, which) {
    go('#sidebarcontents', 
    '/home?finished=' + which + '&uuid=' + uuid,
    '', 
    unavailable, 
    false, 
    loadstories,
    false);
}

$.fn.goDeep = function(levels, func){
    var iterateChildren = function(current, levelsDeep){
        func.call(current, levelsDeep);

        if(levelsDeep > 0)
            $.each(current.children(), function(index, element){
                iterateChildren($(element), levelsDeep-1);
            });
    };

    return this.each(function(){
        iterateChildren($(this), levels);
    });
};

function validatetext() {
    var ids = [ 'textname', 'textvalue', 'textlanguage' ];
    for (var i = 0; i < ids.length; i++) {
         if ($("#" + ids[i]).val() == '') {
            document.getElementById("uploaderror").style.display = 'block';
            return;
         }
    }
    $("#textform").submit();
}

function validatefile() {
    var ids = [ 'uploadfile', 'uploadtype', 'uploadlanguage' ];
    for (var i = 0; i < ids.length; i++) {
         if ($("#" + ids[i]).val() == '') {
            document.getElementById("uploaderror").style.display = 'block';
            return;
         }
    }
    $("#fileform").submit();
}

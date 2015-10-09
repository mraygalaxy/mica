//var jQuery = require('../serve/jquery-1.11.3.js');
//var couch = require('../serve/jquery.couch-1.5.js');
//var $ = require('jquery');
//var $ = require("jquery")(jsdom.jsdom().parentWindow);
//var wait = require('waitfor');
var fs = require('fs');
var http = require('http');
var jsdom = require("jsdom"); 
var $ = require("jquery")(jsdom.jsdom().createWindow);
var jquery = fs.readFileSync("../serve/jquery-1.11.3.js", "utf-8");
var mica = fs.readFileSync('../serve/mica.js', 'utf-8');
var head = fs.readFileSync('../serve/head.js', 'utf-8');
var couch = require('couchjs');
//eval(fs.readFileSync('../serve/mica.js')+'');

var Docker = require('dockerode');
var docker = new Docker({socketPath: '/var/run/docker.sock'});

function remove(container, next) {
	container.remove(function (err, data) {
	  if (err) {
	      console.log(err);
	  } else {
	      console.log("Container removed.");
		if(next)
		      next(container, null);
	  }
	});
}
function cleanup(name, next) {
	console.log("Looking up: " + name);
        var container = docker.getContainer(name);
	if (container) {
		container.inspect(function (err, data) {
			if (err) {
			    console.log("No container to cleanup: " + name);
				if(next)
				    next(container, null);
			} else {
				console.log("Container inspected: " + data);
				if (data.State.Running) {
					container.stop(function (err, data) {
						if (err) 
						      console.log(err);
						else {
							console.log("Container stopped.");
							remove(container, next);
						}
					});
				} else {
				     remove(container, next);
				}
			  }
		});
	} else {
		console.log("No such container: " + name);
	}
}

var options = {
	Image: 'micadev7', 
	Cmd: ['/home/mrhines/mica/restart.sh'], 
	name: 'couchdev',
	Tty : true,
	PortBindings: {
            "22/tcp": [{
	            "HostIp": "0.0.0.0",
                    "HostPort": "2222"
	     }],
            "5984/tcp": [{
	            "HostIp": "0.0.0.0",
                    "HostPort": "5984"
	    }],
            "6984/tcp": [{
	            "HostIp": "0.0.0.0",
                    "HostPort": "6984"
	    }],
            "7984/tcp": [{
	            "HostIp": "0.0.0.0",
                    "HostPort": "7984"
	    }]
        }
}

var loc = {
    host: 'localhost',
    port: 80,
    path: '/'
};

function start(result, next) {
	docker.createContainer(options, function (err, container) {
	  if (err) 
	      console.log(err);
	  else {
		console.log("Container created.");
		container.start(function (err, data) {
			if (err) 
			      console.log(err);
			else {
				console.log("Container started.");

                jsdom.env({
                  url: "http://localhost",
                  src: [jquery, mica, head],
                  done: function (err, window) {
                    var $ = window.$;
                    console.log("address: " + $("#address").val());
                    //form_loaded(false, true);
                    //cleanup(options.name, null);
                  }
                });
			}
		  });
	  }
	});

}
cleanup(options.name, start);

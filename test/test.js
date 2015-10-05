var fs = require('fs');
var http = require('http');
//var jQuery = require('../serve/jquery-1.11.3.js');
var $ = require('jquery');
//var couch = require('../serve/jquery.couch-1.5.js');
var couch = require('couchjs');
//var mica = require('../serve/mica.js');
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
				//cleanup(options.name, null);

				var html = '';
				http.get(options, function(res) {
				    res.on('data', function(data) {
					// collect the data chunks to the variable named "html"
					html += data;
				    }).on('end', function() {
					var title = $(html).find('title').text();
					console.log("HTML title:" + title);
				     });
				});
			}
		  });
	  }
	});

}
cleanup(options.name, start);

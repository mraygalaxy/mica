var Docker = require('dockerode');
var docker = new Docker({socketPath: '/var/run/docker.sock'});

// create a container entity. does not query API
var container = docker.getContainer('couchdev');

// query API for container info
container.inspect(function (err, data) {
  console.log(data);
});

/*
container.start(function (err, data) {
  if (err) 
      console.log(err);
  console.log(data);
});

container.remove(function (err, data) {
  console.log(data);
});

docker.createContainer({Image: 'ubuntu', Cmd: ['/bin/bash'], name: 'ubuntu-test'}, function (err, container) {
  container.start(function (err, data) {
    //...
  });
});
*/

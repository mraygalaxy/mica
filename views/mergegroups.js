{
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:mergegroups:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:mergegroups:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:mergegroups:)/g, '')], doc); } }"
       }
   }
}

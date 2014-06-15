{
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:splits:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:splits:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:splits:)/g, '')], doc); } }"
       }
   }
}

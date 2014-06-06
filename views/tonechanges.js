{
   "_id": "_design/tonechanges",
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:tonechanges:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:tonechanges:.*)/g, ''), doc._id.replace(/MICA:[^:]+:tonechanges:/g, '')], doc); } }"
       }
   }
}

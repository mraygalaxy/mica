{
   "_id": "_design/tonechanges",
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:tonechanges:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:tonechanges:.*)/g, ''), doc._id.replace(/MICA:[^:]+:tonechanges:/g, '')], doc); } }"
       }
   }
}

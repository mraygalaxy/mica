{
   "language": "javascript",
   "views": {
       "allcount": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:memorized:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }",
           "reduce": "_count"
       },
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:memorized:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }"
       }
   }
}

{
   "_id": "_design/mergegroups",
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:mergegroups:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:mergegroups:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:mergegroups:)/g, '')], doc); } }"
       }
   }
}

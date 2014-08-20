{
   "_id": "_design/splits",
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:splits:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:splits:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:splits:)/g, '')], doc); } }"
       }
   }
}

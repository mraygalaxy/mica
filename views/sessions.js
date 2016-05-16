{
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (/MICA:sessions:.*$/.test(doc._id)) { emit([doc._id.replace(/MICA:sessions:/g, '')], doc); } }"
       }
   }   
}

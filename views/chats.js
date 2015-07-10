{
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:chat;[^;]+;[^;]+;[^;:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:chat;|;[^;]+;[^;]+$)/g, '')], doc); } }"
       }
   }   
}

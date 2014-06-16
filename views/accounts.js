{
   "language": "javascript",
   "views":
   {
     "all": {
       "map": "function(doc) { if (doc._id.indexOf('MICA:accounts:') != -1) { emit(doc._id.replace('MICA:accounts:', ''), doc); } }"
     }
   }
}

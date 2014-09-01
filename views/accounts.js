{
   "language": "javascript",
   "views": {
       "all": {
           "map": "function(doc) { if (doc.mica_database != undefined) { emit(doc); } }"
       },
       "allcount": {
           "map": "function(doc) { if (doc.mica_database != undefined) { emit(doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       }
   }   
}

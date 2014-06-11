{
   "_id": "_design/groupings",
   "language": "javascript",
   "views": {
       "allcount": {
           "map": "function(doc) { emit(doc._id, doc); }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "all": {
           "map": "function(doc) { emit(doc._id, doc); }"
       }
       "translating": {
           "map": "function(doc) { if ((doc.translating != undefined) && (doc.translating == true)) { emit(doc.name, doc); } }"
       },
   }
}

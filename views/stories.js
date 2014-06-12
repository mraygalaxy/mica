{
   "_id": "_design/stories",
   "language": "javascript",
   "views": {
       "pages": {
           "map": "function(doc) { if (/pages:[^:]+$/.test(doc._id)) { emit(doc._id.replace(/pages:/g, ''), doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "allpages": {
           "map": "function(doc) { if (/pages:[^:]+$/.test(doc._id)) { emit(doc._id.replace(/pages:/g, ''), doc); } }"
       },
       "original": {
           "map": "function(doc) { if (/original:[^:]+$/.test(doc._id)) { emit(doc._id.replace(/original:/g, ''), doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "alloriginal": {
           "map": "function(doc) { if (/original:[^:]+$/.test(doc._id)) { emit(doc._id.replace(/original:/g, ''), doc); } }"
       }
   }
}

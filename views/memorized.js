{
   "_id": "_design/memorized",
   "language": "javascript",
   "views": {
       "allcount": {
           "map": "function(doc) { if (/MICA:[^:]+:memorized:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:memorized:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }"
       }
   }
}

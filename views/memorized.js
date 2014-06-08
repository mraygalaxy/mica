{
   "_id": "_design/memorized",
   "language": "javascript",
   "views": {
       "allcount": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:memorized:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:memorized:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }"
       }
   }
}

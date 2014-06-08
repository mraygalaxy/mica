{
   "_id": "_design/stories",
   "language": "javascript",
   "views": {
       "test": {
           "map": "function(doc) { if (doc.translating != undefined) { emit([doc.name], doc); } }"
       },
       "translating": {
           "map": "function(doc) { if ((doc._id.match(/MICA:[^:]+:stories:[^:]+$/g).length == 1) && (doc.translating != undefined) && (doc.translating == true)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "pages": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "allpages": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }"
       },
       "original": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:original:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "alloriginal": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:original:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }"
       }
   }
}

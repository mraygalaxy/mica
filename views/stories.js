{
   "_id": "_design/stories",
   "language": "javascript",
   "views": {
       "translating": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+$/.test(doc._id) && (doc.translating != undefined) && (doc.translating == true)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "all": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "pages": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "allpages": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }"
       },
       "original": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+:original:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       },
       "alloriginal": {
           "map": "function(doc) { if (/MICA:[^:]+:stories:[^:]+:original:[^:]+$/.test(doc._id)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }"
       }
   }
}

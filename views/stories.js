{
   "_id": "_design/stories",
   "language": "javascript",
   "views": {
       "translating": {
           "map": "function(doc) { if ((doc._id.match(/MICA:[^:]+:stories:[^:]+$/g).length == 1) && (doc.translating != undefined) && (doc.translating == true)) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "all": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc.name], doc); } }"
       },
       "pages": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }",
           "reduce": "_count"
       },
       "allpages": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:pages:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:pages:/g, '')], doc); } }"
       },
       "original": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:original:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }",
           "reduce": "_count"
       },
       "alloriginal": {
           "map": "function(doc) { if (doc._id.match(/MICA:[^:]+:stories:[^:]+:original:[^:]+$/g).length == 1) { emit([doc._id.replace(/(MICA:|:stories:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:stories:|:original:.*)/g, ''), doc._id.replace(/MICA:[^:]+:stories:[^:]+:original:/g, '')], doc); } }"
       }
   }
}

{
   "_id": "_design/memorized2",
   "views": {
       "all": {
           "map": "function(doc) { if ((/MICA:[^:]+:memorized:[^:]+$/g).test(doc._id)) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }"
       },
       "allcount": {
           "map": "function(doc) { var lang = ''; if ('source_language' in doc) { lang = doc['source_language']; } else { lang = 'zh-CHS'; if ('sromanization' in doc) { if (doc['sromanization'].length == 0) { lang = 'en'; } else if (doc['sromanization'].length == 1 && (doc['source'].join('') == doc['sromanization'][0])) { if (doc['source'].length > 1 || (doc['source'][0] != doc['sromanization'][0])) { if (doc['target'].length == 0 || doc['sromanization'][0] != doc['target'][0]) { lang = 'en'; } } } } } if ((/MICA:[^:]+:memorized:[^:]+$/g).test(doc._id)) { emit([doc._id.replace(/(MICA:|:memorized:.*)/g, ''), lang, doc._id.replace(/(MICA:[^:]+:memorized:)/g, '')], doc); } }",
           "reduce": "function(keys, values, rereduce) { if (rereduce) { return sum(values); } else { return values.length; } }"
       }
   },
   "language": "javascript"
}

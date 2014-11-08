{
   "_id": "_design/download",
   "language": "javascript",
   "filters": {
       "mobile": "function(doc, req){ var stories = req.query.stories.split (','); var files = req.query.files.split (','); if (/MICA:[^:]+:stories:[^:]+:original:[^:]+$/.test(doc._id)){ for(var idx = 0; idx < stories.length; idx++) { if (doc._id.indexOf(stories[idx]) != -1) { return true; }; } return false; } if (/MICA:[^:]+:stories:[^:]+:pages:[^:]+$/.test(doc._id)){ for(var idx = 0; idx < stories.length; idx++) { if (doc._id.indexOf(stories[idx]) != -1) { return true; }; } return false; } if (/MICA:filelisting_[^:]+$/.test(doc._id)){ for(var idx = 0; idx < files.length; idx++) { if (doc._id.indexOf(files[idx]) != -1) { return true; }; } return false; } if (/<PDFPage: Resources=/.test(doc._id)) { return false; } return true; }"
   }
}

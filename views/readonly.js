{
   "_id": "_design/readonly",
   "validate_doc_update": "function(newDoc, oldDoc, userCtx, secObj) {if (userCtx.roles.length != 0 && userCtx.roles[0] != '_admin') throw({forbidden : 'read-only for ' + userCtx.roles});}"
}

{ "_id": "_design/conflicts"
, "views":
  { "conflicts":
    { "options": {"include_design": true}
    , "map": "function(doc) { if(doc._conflicts) emit(doc._id, doc._conflicts); }"
    }
  }
}

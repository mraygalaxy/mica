var _callbacks_ = {
    'loadWords': function(rep){
        var success = rep[0],
            reply = rep[1][0],
            word = reply[0],
            words = reply[1],
            lens = reply[2];

        if (typeof lens == 'undefined') {
            lens = new Array(words.length);
            for (var i = 0; i < lens.length; i++) {
                lens[i] = word.length;
            }
        }
        $.wordDatabase.setChoices(word, words, lens);
    }
};

(function($){

    function Word(name, choices, options){
        var self = this;

        self.defaultOptions = {
            pending: false,
            length: choices.length
        };

        self.name = name;
        self.choices = $.extend(true, [], choices);
        self.lens = []; // matched lengths
        self.num = (typeof options.num == 'undefined') ? choices.length : options.num;
        self.options = $.extend({}, self.defaultOptions, options);
        self.pending = self.options.pending;
        self.traditional = self.options.traditional === true ? true : false;

        self.setChoices = function(choices, lens){
            self.choices = $.extend(true, [], choices);
            self.lens = lens;
            self.pending = false;
            //self.num = self.choices.length;
        }

    }

    function WordDatabase(){
        var self = this;
        self.words = {};
        self.loading = {};
        self.traditional = false; // convert simplified to traditional if true

        self.getChoices = function(word){
            var word = self.words[word];
            if (word && word.traditional == self.traditional){
                return word.choices;
            }
            return [];
        }

        self.getLength = function(word, choice) {
            var word = self.words[word];
            if (word){
                return word.lens[choice];
            }
            return word.length;
        }

        self.hasWord = function(word, num){
            hasWord = (self.words.hasOwnProperty(word) && self.words[word].num >= num);
            if (hasWord){
                var w = self.words[word];
                if (w.traditional != self.traditional) {
                    return false;
                }
                if (w.pending === true && w.traditional != self.traditional) {
                    return true;
                }
            }
            return hasWord;
        }

        self.addWord = function(word, num){
            num = (typeof num == 'undefined' ? 10 : num);
            self.words[word] = new Word(word, [], {pending: true, num: num, traditional: self.traditional});
        };

        self.setChoices = function(word, choices, lens, options){
            if (word.length > 0 && choices instanceof Array && self.words[word]) {
                wordObj = self.words[word];
                if (self.traditional && typeof $.toTraditional !== 'undefined') {
                    var convert = function(simpArray){
                        var ar = [];

                        for (var i = 0; i < simpArray.length; i++) {
                            var fullWord = $.toTraditional(simpArray[i]);
                            ar.push(fullWord);
                        }
                        return ar;
                    }
                    choices = convert(choices);
                }
                if (wordObj.pending === true) {
                    if (choices.length < wordObj.num) { 
                        // we've reached the end of the pages,
                        // so add a stop word to indicate that
                        choices.push(word);
                        lens.push(word.length);
                    }
                }
                wordObj.setChoices(choices, lens);

                return self.words[word];
            }
            return false;
        };
    };

    $.wordDatabase = new WordDatabase();

    $.fn.extend({
        insertAtCaret: function(myValue){
          return this.each(function(i) {
            if (document.selection) {
              //For browsers like Internet Explorer
              this.focus();
              sel = document.selection.createRange();
              sel.text = myValue;
              this.focus();
            }
            else if (this.selectionStart || this.selectionStart == '0') {
              //For browsers like Firefox and Webkit based
              var startPos = this.selectionStart;
              var endPos = this.selectionEnd;
              var scrollTop = this.scrollTop;
              this.value = this.value.substring(0, startPos)+myValue+this.value.substring(endPos,this.value.length);
              this.focus();
              this.selectionStart = startPos + myValue.length;
              this.selectionEnd = startPos + myValue.length;
              this.scrollTop = scrollTop;
            } else {
              this.value += myValue;
              this.focus();
            }
          })
        }
    });

    $.chineseInput = function(el, options){
        // To avoid scope issues, use 'self' instead of 'this'
        // to reference this class from internal events and functions.
        var self = this;
        
        // Access to jQuery and DOM versions of element
        self.$el = $(el);
        self.el = el;

        self.id = String(parseInt(Math.random() * 10000) * parseInt(Math.random() * 10000));

         // Set null options object if no options are provided
        if(!options || typeof options !== 'object') options = {};

         // Sanitize option data
        if(typeof options.input !== 'object') options.input = {initial: 'simplified', allowChange: true};
        if(typeof options.input.initial !== 'string') options.input.initial = 'simplified';
        if(options.input.initial.toLowerCase() != 'simplified' && options.input.initial.toLowerCase() != 'traditional') options.input.initial = 'simplified';
        options.active = options.active == true;
        options.input.allowChange = options.input.allowChange == true; // set it to boolean value true if it evaluates to true
        options.allowHide = options.allowHide == true;

	var foo = "bar";

	$.receivePush = function(select_idx) {
	    self.makeSelection(select_idx - 1);
	    self.updateDialog();
        }

        self.resetCurrent = function() {
            self.currentText = '';
            self.currentPage = 0;
            self.currentSelection = 1;
            self.lastPage = false;
        }

        self.clearOld = function(amount) {
            var txt = $("#msgArea").val(); 
            if (amount == -1) {
                amount = self.currentText.length;
            } else if(amount == -2) {
                $("#msgArea").val('');
                return;
            }

            $("#msgArea").val(txt.substring(0, txt.length - amount));
        }


        self.resetCurrent();
        self.inputText = '';
        self.clearOld(-2);
        document.getElementById("msgArea").focus();
        //self.options = [];
        self.html = '<ul class="options"></ul>';
        self.url = '//www.google.com/inputtools/request?ime=pinyin&ie=utf-8&oe=utf-8&app=translate&uv'
        self.paramNames = {'text': 'text',
                           'num': 'num',
                           'callback': 'cb'}
        self.defaultNum = 10; // default number of options to load
        
        // Add a reverse reference to the DOM object
        self.$el.data("chineseInput", self);
        
        self.nothing = function() {
	    console.log("keydown called, but doing nothing.");
            event.preventDefault();
            return false; 
        }
        self.init = function(){
            
            self.options = $.extend({},$.chineseInput.defaultOptions, options);
            
	     self.enter = function( event ) {
		
		    if(event.which ==13)  //13 is for enterkey
	     {
		 event.preventDefault();
	      	 console.log("GOT ENTER EVENT!!!!!!"); 
		 self.keyPress(event);
	     }
	    }

	    $("#msgArea").on( "keyup", self.enter);
	    $("#msgArea").bind('input propertychange', self.keyPress);
	    $('#sendForm').submit(function(ev) {ev.preventDefault(); self.keyPress(ev)});

            self.$toolbar = $('<div id="chinese-toolbar-' + self.id + '"></div>');
            self.$toolbar.insertAfter(self.$el);
            self.$toolbar.css({'position': 'absolute', 'z-index': 1000}).show();
            self.reposition(self.$toolbar);

            $.wordDatabase.traditional = false;

            $(window).resize($.proxy(function() { // TODO: attach to textarea resize event
                this.self.updateDialog();
                this.self.reposition();
            }, {'self': self}));

            self.reposition();
        };
        

        /*
                    switch(event.which){
                        case 37: // left 
                            self.previousChoice();
                            return false;
                        case 39: // right
                            self.nextChoice();
                            return false;
                    }
                }
        */

	self.last_key_was_backspace = false;

        self.keyPress = function(event){
            if (self.options.active) {
                var beforeCheck = $("#msgArea").val();
                var key = '';
                var backspace = 0;
		self.last_key_was_backspace = false;
                console.log("inputText: " + self.inputText + " beforeCheck " + beforeCheck + " currentText " + self.currentText);
                if (beforeCheck.length > self.inputText.length) {
                    var diff = (beforeCheck.length - self.inputText.length);
                    if (self.inputText.length == 0) {
                        key = beforeCheck;
                    } else {
                        key = beforeCheck.substring(beforeCheck.length - diff, beforeCheck.length)
                    }
                } else if(beforeCheck.length < self.inputText.length) {
                    backspace = self.inputText.length - beforeCheck.length;
                } else {
                    if (self.currentText.length == 0) {
                        self.sendText();
                    }
		    console.log("Returning early. Booooooooooooo.");
                    return false;
                }
                if (/[a-zA-Z\?\=\)\-\^\%\$\#\@\!\~\`\-\_\(\+\=\*\&\'\"\;\:\]\[\}\{\/\<\>]/.test(key)){ 
                    console.log("Caught key " + key);

                //if (/[a-zA-Z]/.test(key)){ 
                    self.inputText = beforeCheck;
                    // pressed a character
                    if (self.currentText.length <= 20){ 
                        // set maximum num characters to arbitrary 20 limit
                        self.currentText += key;
                    }
                } else if (self.currentText.length > 0) {
                    if (key == ' '){ 
                        // pressed space
                        /* I don't like the behavior of pressing space
                         * for chinese to get the current selection.
                         * just put the pinyin directly.
                         */

                        var pair = getPairs(); 
                        var chat_source_language = pair[0];
                        var chat_target_language = pair[1];  
                        //if (chat_target_language != "zh" && chat_target_language != "zh-CHS") {
                        //    self.clearOld(-1);
                        //    self.makeSelection(self.currentSelection - 1);
                        //} else {
                            self.resetCurrent();
                        //}
                        self.inputText = $("#msgArea").val();
                    } else if (/[1-8]/.test(key)) { 
                      // pressed number between 1 and 8
                        self.clearOld(1);
			$.receivePush(parseInt(key));
			return false;
                    } else if (key == ',') { // go to previous page
                        self.previousPage();
                    } else if (key == '.') { // go to next page
                        self.nextPage();
                    } else if (key == '') {
                        if (backspace) {
			    self.last_key_was_backspace = true;
                            self.currentText = self.currentText.substring(0, self.currentText.length - backspace);
                            self.inputText = beforeCheck;
                        } else {
                            // enter key pressed -- accept phonetic input
                            self.clearOld(-1);
                            self.addText(self.currentText);
                            self.resetCurrent();
                        }
                    }
                } else {
                    self.inputText = beforeCheck;
                }
                    // enter send text in MICA chat system
                    //self.sendText();
                self.updateDialog();
            }
	    console.log("Finished with keypress now.");
            return false;
        };

        self.sendText = function() {
            if ($("#msgArea").val() != "") {
                if ($("#sendTo").val() == "") {
                    $("#missing").attr("style", "display: block");
                } else {
                    var tval = sendMsg(document.getElementById('sendForm'));
                    if (tval) 
                        appendChat(chat_username, $("#sendTo").val(), tval);
                    else
                        appendChat(chat_username, $("#sendTo").val(), "error");
                }
                self.clearOld(-2);
            }
            self.inputText = "";
            self.clearOld(-2);
            self.resetCurrent();
            self.updateDialog();
        }

        self.addText = function(text){
            self.$el.insertAtCaret(text);
        };

        self.nextPage = function(){                
            if (!self.lastPage) {
                self.currentPage += 1;
            }
            self.updateDialog();
        }

        self.previousPage = function(){
            self.currentPage = parseInt(Math.max(0, self.currentPage - 1));
            self.lastPage = false;
            self.updateDialog();
        }

        self.nextChoice = function(){
            if (self.currentSelection < 8) {
                self.currentSelection += 1;
                self.updateDialog();
            } else {
                self.currentSelection = 1;
                self.nextPage(); 
            }
        }

        self.previousChoice = function(){
            if (self.currentSelection > 1) {
                self.currentSelection -= 1;
                self.updateDialog();
            } else if (self.currentPage > 0) {
                self.currentSelection = 8;
                self.previousPage(); 
            }
        }

        self.makeSelection = function(selectionIndex){
            var choices = $.wordDatabase.getChoices(self.currentText);
            selectionIndex += self.currentPage * 8; // add current page to index
            if (selectionIndex < 0) { 
                self.clearOld(-1);
                // if selection is smaller than zero, we use the text input as is, effectively canceling smart input
                self.addText(self.currentText);
                self.resetCurrent();
            }
            if (choices && selectionIndex < choices.length){
                self.clearOld(-1);
                choice = choices[selectionIndex];
                len = $.wordDatabase.getLength(self.currentText, selectionIndex);
                self.addText(choice);
                self.resetCurrent();
            }

	    self.inputText = $("#msgArea").val();
        };

        self.reposition = function($el){
            var $toolbar = $el;
            if (!$toolbar){
                $toolbar = self.$toolbar;
            }
            $toolbar.css({'padding': '0 0 10px 5px'}).
                     position({my: 'left bottom',
                                at: 'left bottom',
                                of: self.$el,
                                collision: "none"});
        }

        self.updateDialog = function(){
            if (!self.last_key_was_backspace && self.currentText.length > 0) {

                var pair = getPairs(); 

                var chat_source_language = pair[0];
                var chat_target_language = pair[1];  

		/*
                if (chat_target_language == "zh" || chat_target_language == "zh-CHS") {
                    var options = [self.currentText];
                } else {
                    var options = self.getOptionsFromDatabase(self.currentText, self.currentPage);
                }
		*/

                //if (true || options && options.length){
                    var $box = $('#chinese-ime');
                    if (!$box.size()){
                        $box = $(document.createElement('div')).
                                attr({'id': 'chinese-ime'}).
                                html(self.html)
                        $('body').append($box);
                    }
                    //$box.find('.typing').text(self.currentText);
                    var lis = [];

                    /* For now, assume that the target language
                     * is the same as the language the user's native
                     * language. We can fix this later. 
                     */
                    var chat_language = chat_target_language;
                     
                    var micaurl = "/api=chat_ime&source=" + self.currentText + "&mode=read&target_language=" + chat_target_language + "&source_language=" + chat_source_language + "&lang=" + chat_language;

                    $.get(micaurl, "", $.proxy(function(response, success){
                        console.log("Response: " + response); 
			var data = JSON.parse(response);
			if(data.success)  {
				if (!$.wordDatabase.hasWord(data.result.word, 10)){
					$.wordDatabase.addWord(data.result.word, 10);
					$.wordDatabase.setChoices(data.result.word, data.result.chars, data.result.lens);
				}

				$box.find('ul').html(data.result.human);
			} else {
				$box.find('ul').html(data.desc);
				//self.callAjax(self.currentText, self.currentPage);
			}

                        $box.show();
                        var caretPosition = self.$el.getCaretPosition();
                        $box.css({
                            position: 'absolute',
                            left: self.$el.offset().left + caretPosition.left,
                            top: self.$el.offset().top - (4 * caretPosition.top)
                        });
                    }, {}), 'html');

            } else {
                var $box = $('#chinese-ime').hide();
            }
        };

        self.getOptionsFromDatabase = function(text, page, num){
            if (typeof page == 'undefined') { page = self.currentPage; }
            if (typeof num == 'undefined') { num = 8; }
            var options = $.wordDatabase.getChoices(text);
            if (options && options.length >= (page + 1) * num) {
                // we have options in the database already, and enough of them
                return options.slice(page*num, (page+1)*num);
            } else if (options && options[options.length-1] == text) {
                // if the last option is the text itself, it means we've exhausted all suggestions
                self.lastPage = true;
                return options.slice(page*num);
            }
            return false; // we need to call ajax first
        };
        
        self.callAjax = function(text, page, num, callback){
            var params = {};
            num = (typeof num == 'undefined' ? self.defaultNum : num);
            num = num + parseInt(Math.floor(page / 2)) * num;
            params[self.paramNames['text']] = text;
            params[self.paramNames['num']] = num; // assuming page length is 10 here

            if (typeof callback != 'undefined') {
                params[self.paramNames['callback']] = callback;
            } else {
                params[self.paramNames['callback']] = '_callbacks_.loadWords';
            }
            if (!$.wordDatabase.hasWord(text, num)){
                $.wordDatabase.addWord(text, num);
                var pairs = getPairs();
                if (pairs[1] == "zh" || pairs[1] == "zh-CHS") { 

                    self.currentText = text;
                    self.updateDialog();
                } else {
                    //$.get(self.url, params, $.proxy(function(response, success){
                        self.updateDialog();
                    //}, {'text': text, 'page': page, 'num': num, 'callback': callback}), 'script');
                }
            }
        };

        // Run initializer
        self.init();
    };
    
    $.chineseInput.defaultOptions = {
        debug: false
    };
    
    $.fn.chineseInput = function(options){
        return this.each(function(){
            (new $.chineseInput(this, options));
        });
    };
    
})(jQuery);

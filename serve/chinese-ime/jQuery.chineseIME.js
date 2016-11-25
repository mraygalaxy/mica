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
        self.el.prefid = options.unique;
     	self.el.last_key_was_backspace = false;
        self.el.wordDatabase = new WordDatabase();

        self.el.id = String(parseInt(Math.random() * 10000) * parseInt(Math.random() * 10000));

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

        self.el.receivePush = function(select_idx) {
            self.el.makeSelection(select_idx - 1);
            self.el.updateDialog();
        }

        self.el.resetCurrent = function() {
            self.el.currentText = '';
            self.el.currentPage = 0;
            self.el.currentSelection = 1;
            self.el.lastPage = false;
        }

        self.el.clearOld = function(amount) {
            var txt = self.$el.val(); 
            if (amount == -1) {
                amount = self.el.currentText.length;
            } else if(amount == -2) {
                self.$el.val('');
                return;
            }

            self.$el.val(txt.substring(0, txt.length - amount));
        }


        self.el.resetCurrent();
        self.el.inputText = '';
        self.el.clearOld(-2);
        self.$el.focus();
        //self.options = [];
        self.html = "<ul data-role='none' class='options' style='color: black'></ul>";
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
        self.el.init = function(){
            self.el.options = $.extend({},$.chineseInput.defaultOptions, options);
            
            self.$el.on( "keypress", self.el.keyPress);
	        self.$el.on( "keyup", self.el.keyPress);
	        self.$el.unbind().bind('input propertychange', self.el.keyPress);
	        //$('#sendForm').submit(function(ev) {ev.preventDefault(); self.el.keyPress(ev)});

            self.el.$toolbar = $('<div id="chinese-toolbar-' + self.id + '"></div>');
            self.el.$toolbar.insertAfter(self.$el);
            self.el.$toolbar.css({'position': 'absolute', 'z-index': 1000}).show();
            self.el.reposition(self.el.$toolbar);

            self.el.wordDatabase.traditional = false;

            $(window).resize($.proxy(function() { // TODO: attach to textarea resize event
                this.self.el.updateDialog();
                this.self.el.reposition();
            }, {'self': self}));

            self.el.reposition();
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

        self.el.keyPress = function(event){
            if (self.el.options.active) {
                var beforeCheck = self.$el.val() || "";
                var key = '';
                var backspace = 0;
                self.el.last_key_was_backspace = false;
                console.log("inputText: " + self.el.inputText + " beforeCheck " + beforeCheck + " currentText " + self.el.currentText);
                if (beforeCheck.length > self.el.inputText.length) {
                    var diff = (beforeCheck.length - self.el.inputText.length);
                    if (self.el.inputText.length == 0) {
                        key = beforeCheck;
                    } else {
                        key = beforeCheck.substring(beforeCheck.length - diff, beforeCheck.length)
                    }
                } else if(beforeCheck.length < self.el.inputText.length) {
                    backspace = self.el.inputText.length - beforeCheck.length;
                } else {
                    if (self.el.currentText.length == 0) {
                        console.log("No new text. Sending what's left.")
                        self.el.sendText();
                    }
                    console.log("Returning early. Booooooooooooo.");
                    return false;
                }
                if (/[a-zA-Z\?\=\)\-\^\%\$\#\@\!\~\`\-\_\(\+\=\*\&\'\"\;\:\]\[\}\{\/\<\>]/.test(key)){ 
                    console.log("Caught key " + key);

                //if (/[a-zA-Z]/.test(key)){ 
                    self.el.inputText = beforeCheck;
                    // pressed a character
                    if (self.el.currentText.length <= 20){ 
                        // set maximum num characters to arbitrary 20 limit
                        self.el.currentText += key;
                    }
                } else if (self.el.currentText.length > 0) {
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
                        //    self.el.clearOld(-1);
                        //    self.el.makeSelection(self.el.currentSelection - 1);
                        //} else {
                            self.el.resetCurrent();
                        //}
                        self.el.inputText = self.$el.val();
                    } else if (/[1-8]/.test(key)) { 
                      // pressed number between 1 and 8
                        self.el.clearOld(1);
                        self.el.receivePush(parseInt(key));
                        return false;
                    } else if (key == ',') { // go to previous page
                        self.el.previousPage();
                    } else if (key == '.') { // go to next page
                        self.el.nextPage();
                    } else if (key == '') {
                        if (backspace) {
                            self.el.last_key_was_backspace = true;
                            self.el.currentText = self.el.currentText.substring(0, self.el.currentText.length - backspace);
                            self.el.inputText = beforeCheck;
                        } else {
                            // enter key pressed -- accept phonetic input
                            self.el.clearOld(-1);
                            self.el.addText(self.el.currentText);
                            self.el.resetCurrent();
                        }
                    }
                } else {
                    self.el.inputText = beforeCheck;
                }
                    // enter send text in MICA chat system
                    //self.sendText();
                self.el.updateDialog();
            }
            console.log("Finished with keypress now.");
            return false;
        };

        self.el.sendText = function() {
            if (self.$el.val() != "") {
                var e = $.Event('keydown', { keyCode: 13 });
                self.$el.trigger(e);
                self.el.clearOld(-2);
            }
            self.el.inputText = "";
            self.el.clearOld(-2);
            self.el.resetCurrent();
            self.el.updateDialog();
        }

        self.el.addText = function(text){
            self.$el.insertAtCaret(text);
        };

        self.el.nextPage = function(){                
            if (!self.el.lastPage) {
                self.el.currentPage += 1;
            }
            self.el.updateDialog();
        }

        self.el.previousPage = function(){
            self.el.currentPage = parseInt(Math.max(0, self.el.currentPage - 1));
            self.el.lastPage = false;
            self.el.updateDialog();
        }

        self.el.nextChoice = function(){
            if (self.el.currentSelection < 8) {
                self.el.currentSelection += 1;
                self.el.updateDialog();
            } else {
                self.el.currentSelection = 1;
                self.el.nextPage(); 
            }
        }

        self.el.previousChoice = function(){
            if (self.el.currentSelection > 1) {
                self.el.currentSelection -= 1;
                self.el.updateDialog();
            } else if (self.el.currentPage > 0) {
                self.el.currentSelection = 8;
                self.el.previousPage(); 
            }
        }

        self.el.makeSelection = function(selectionIndex){
            var choices = self.el.wordDatabase.getChoices(self.el.currentText);
            selectionIndex += self.el.currentPage * 8; // add current page to index
            if (selectionIndex < 0) { 
                self.el.clearOld(-1);
                // if selection is smaller than zero, we use the text input as is, effectively canceling smart input
                self.el.addText(self.el.currentText);
                self.el.resetCurrent();
            }
            if (choices && selectionIndex < choices.length){
                self.el.clearOld(-1);
                choice = choices[selectionIndex];
                len = self.el.wordDatabase.getLength(self.el.currentText, selectionIndex);
                self.el.addText(choice);
                self.el.resetCurrent();
            }

            self.el.inputText = self.$el.val();
        };

        self.el.reposition = function($el){
            var $toolbar = $el;
            if (!$toolbar){
                $toolbar = self.el.$toolbar;
            }
            $toolbar.css({'padding': '0 0 10px 5px'}).
                     position({my: 'left bottom',
                                at: 'left bottom',
                                of: self.$el,
                                collision: "none"});
        }

        self.el.last_api = '';
        self.el.updateDialog = function(){
                
            if (!self.el.last_key_was_backspace && self.el.currentText.length > 0) {

                var pair = getPairs(); 

                var chat_source_language = pair[0];
                var chat_target_language = pair[1];  

		/*
                if (chat_target_language == "zh" || chat_target_language == "zh-CHS") {
                    var options = [self.el.currentText];
                } else {
                    var options = self.getOptionsFromDatabase(self.el.currentText, self.el.currentPage);
                }
		*/
                var chat_language = chat_target_language;
                    
                var micaurl = "chat_ime&ime=1&mode=read&source=" + self.el.currentText + "&target_language=" + chat_target_language + "&source_language=" + chat_source_language + "&lang=" + chat_language;

                if (micaurl == self.el.last_api) {
                        console.log("Ignoring duplicate api request from wierd keypress");
                        return false;
                }

                self.el.last_api = micaurl;

                //if (true || options && options.length){
                var $box = $('#chinese-ime');
                if (!$box.size()){
                        $box = $(document.createElement('div')).
                                attr({'id': 'chinese-ime'}).
                                html(self.html)
                        $('#chat_content').append($box);
                }
                    //$box.find('.typing').text(self.el.currentText);

                 go(false, micaurl, unavailable(false),   
                        function(json, opaque){
                            console.log("Response: " + json); 
                            if(json.success)  {
                                if (!self.el.wordDatabase.hasWord(json.result.word, 10)){
                                    self.el.wordDatabase.addWord(json.result.word, 10);
                                    self.el.wordDatabase.setChoices(json.result.word, json.result.chars, json.result.lens);
                                }

                                var boxul = $box.find('ul');
                                boxul.html(open_or_close(json.result.human));
                                boxul.attr("prefid", self.el.prefid);
                            } else {
                                $box.find('ul').html(open_or_close(json.desc));
                            }

                            $box.show();
                            var caretPosition = self.$el.getCaretPosition();
                            $box.css({
                                position: 'absolute',
                                left: self.$el.offset().left + caretPosition.left,
                                bottom: caretPosition.top + 15
                            });
                }, false);

            } else {
                var $box = $('#chinese-ime').hide();
            }
        };

        self.el.getOptionsFromDatabase = function(text, page, num){
            if (typeof page == 'undefined') { page = self.el.currentPage; }
            if (typeof num == 'undefined') { num = 8; }
            var options = self.el.wordDatabase.getChoices(text);
            if (options && options.length >= (page + 1) * num) {
                // we have options in the database already, and enough of them
                return options.slice(page*num, (page+1)*num);
            } else if (options && options[options.length-1] == text) {
                // if the last option is the text itself, it means we've exhausted all suggestions
                self.el.lastPage = true;
                return options.slice(page*num);
            }
            return false; // we need to call ajax first
        };
        
        // Run initializer
        self.el.init();
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

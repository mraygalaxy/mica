#!/usr/bin/python
# -*- coding: utf-8 -*-
import struct
import types
import gzip
import sys

class IfoFileException(Exception):
    """Exception while parsing the .ifo file.
    Now version error in .ifo file is the only case raising this exception.
    """
    
    def __init__(self, description = "IfoFileException raised"):
        """Constructor from a description string.
        
        Arguments:
        - `description`: a string describing the exception condition.
        """
        self._description = description
    def __str__(self):
        """__str__ method, return the description of exception occured.
        
        """
        return self._description

class IfoFileReader(object):
    """Read infomation from .ifo file and parse the infomation a dictionary.
    The structure of the dictionary is shown below:
    {key, value}
    """
    
    def __init__(self, db, filename):
        """Constructor from filename.
        
        Arguments:
        - `filename`: the filename of .ifo file of stardict.
        May raise IfoFileException during initialization.
        """
        self.db = db
        if "_ifo" not in self.db :
            self.db["_ifo"] = dict()

            with open(filename, "r") as ifo_file:
                self.db["_ifo"]["dict_title"] = ifo_file.readline() # dictionary title

                line = ifo_file.readline() # version info
                key, equal, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # check version info, raise an IfoFileException if error encounted
                if key != "version":
                    raise IfoFileException("Version info expected in the second line of {!r:s}!".format(filename))

                if value != "2.4.2" and value != "3.0.0":
                    raise IfoFileException("Version expected to be either 2.4.2 or 3.0.0, but {!r:s} read!".format(value))

                self.db["_ifo"][key] = value

                # read in other infomation in the file
                for line in ifo_file:
                    key, equal, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    self.db["_ifo"][key] = value

                # check if idxoffsetbits should be discarded due to version info

                if self.db["_ifo"]["version"] == "3.0.0" and "idxoffsetbits" in self.db["_ifo"]:
                    del self.db["_ifo"]["version"]

    def get_ifo(self, key):
        """Get configuration value.
        
        Arguments:
        - `key`: configuration option name
        Return:
        - configuration value corresponding to the specified key if exists, otherwise False.
        """
        if key not in self.db["_ifo"]:
            return False

        return self.db["_ifo"][key]

class IdxFileReader(object):
    """Read dictionary indexes from the .idx file and store the indexes in a list and a dictionary.
    The list contains each entry in the .idx file, with subscript indicating the entry's origin index in .idx file.
    The dictionary is indexed by word name, and the value is an integer or a list of integers pointing to
    the entry in the list.
    """
    
    def __init__(self, db, filename, compressed = False, index_offset_bits = 32):
        """
        
        Arguments:
        - `filename`: the filename of .idx file of stardict.
        - `compressed`: indicate whether the .idx file is compressed.
        - `index_offset_bits`: the offset field length in bits.
        """
        self.db = db
        self._offset = 0
        if "_word_idx" not in self.db or "_index_idx" not in self.db :
            if compressed:
                with gzip.open(filename, "rb") as index_file:
                    self._content = index_file.read()
            else:
                with open(filename, "r") as index_file:
                    self._content = index_file.read()
            self._index = 0
            self._index_offset_bits = index_offset_bits
            self.db["_word_idx"] = dict()
            self.db["_index_idx"] = list()
            for word_str, word_data_offset, word_data_size, index in self:
                self.db["_index_idx"].append((word_str, word_data_offset, word_data_size))
                if word_str in self.db["_word_idx"]:
                    if isinstance(self.db["_word_idx"][word_str], types.ListType):
                        self.db["_word_idx"][word_str].append(len(self.db["_index_idx"])-1)
                    else:
                        self.db["_word_idx"][word_str] = [self.db["_word_idx"][word_str], len(self.db["_index_idx"])-1]
                else:
                    self.db["_word_idx"][word_str] = len(self.db["_index_idx"])-1

            del self._content
            del self._index_offset_bits
            del self._index

    def __iter__(self):
        """Define the iterator interface.
        
        """
        return self

    def next(self):
        """Define the iterator interface.
        
        """
        if self._offset == len(self._content):
            raise StopIteration
        word_data_offset = 0
        word_data_size = 0
        end = self._content.find("\0", self._offset)
        word_str = self._content[self._offset: end]
        self._offset = end+1
        if self._index_offset_bits == 64:
            word_data_offset, = struct.unpack("!I", self._content[self._offset:self._offset+8])
            self._offset += 8
        elif self._index_offset_bits == 32:
            word_data_offset, = struct.unpack("!I", self._content[self._offset:self._offset+4])
            self._offset += 4
        else:
            raise ValueError
        word_data_size, = struct.unpack("!I", self._content[self._offset:self._offset+4])
        self._offset += 4
        self._index += 1
        return (word_str, word_data_offset, word_data_size, self._index)

    def get_index_by_num(self, number):
        """Get index infomation of a specified entry in .idx file by origin index.
        May raise IndexError if number is out of range.
        
        Arguments:
        - `number`: the origin index of the entry in .idx file
        Return:
        A tuple in form of (word_str, word_data_offset, word_data_size)
        """
        if number >= len(self.db["_index_idx"]):
            raise IndexError("Index out of range! Acessing the {:d} index but totally {:d}".format(number, len(self.db["_index_idx"])))
        return self.db["_index_idx"][number]


    def get_index_by_word(self, word_str):
        """Get index infomation of a specified word entry.
        
        Arguments:
        - `word_str`: name of word entry.
        Return:
        Index infomation corresponding to the specified word if exists, otherwise False.
        The index infomation returned is a list of tuples, in form of [(word_data_offset, word_data_size) ...]
        """
        if word_str not in self.db["_word_idx"]:
            return False
        number =  self.db["_word_idx"][word_str]
        index = list()
        if isinstance(number, types.ListType):
            for n in number:
                index.append(self.db["_index_idx"][n][1:])
        else:
            index.append(self.db["_index_idx"][number][1:])
        return index

class DictFileReader(object):
    """Read the .dict file, store the data in memory for querying.
    """
    
    def __init__(self, db, filename, dict_ifo, dict_index, compressed = False):
        """Constructor.
        
        Arguments:
        - `filename`: filename of .dict file.
        - `dict_ifo`: IfoFileReader object.
        - `dict_index`: IdxFileReader object.
        """
        self.db = db
        self._dict_ifo = dict_ifo
        self._dict_index = dict_index
        self._compressed = compressed
        self._offset = 0
        if "_dict_file" not in self.db :
            self.db["_dict_file"] = list()
            if self._compressed:
                with gzip.open(filename, "rb") as dict_file:
                    while True :
                        char = dict_file.read(1)
                        if char == '' :
                            break
                        self.db["_dict_file"].append(char)
            else:
                with open(filename, "rb") as dict_file:
                    while True :
                        char = dict_file.read(1)
                        if char == '' :
                            break
                        self.db["_dict_file"].append(char)

    def get_dict_by_word(self, word):
        """Get the word's dictionary data by it's name.
        
        Arguments:
        - `word`: word name.
        Return:
        The specified word's dictionary data, in form of dict as below:
        {type_identifier: infomation, ...}
        in which type_identifier can be any character in "mlgtxykwhnrWP".
        """
        result = list()
        indexes = self._dict_index.get_index_by_word(word)
        if indexes == False:
            return False
        sametypesequence = self._dict_ifo.get_ifo("sametypesequence")
        for index in indexes:
            self._offset = index[0]
            size = index[1]
            if sametypesequence:
                result.append(self._get_entry_sametypesequence(size))
            else:
                result.append(self._get_entry(size))
        return result

    def get_dict_by_index(self, index):
        """Get the word's dictionary data by it's index infomation.
        
        Arguments:
        - `index`: index of a word entrt in .idx file.'
        Return:
        The specified word's dictionary data, in form of dict as below:
        {type_identifier: infomation, ...}
        in which type_identifier can be any character in "mlgtxykwhnrWP".
        """
        word, offset, size = self._dict_index.get_index_by_num(index)
        self._offset = offset
        sametypesequence = self._dict_ifo.get_ifo("sametypesequence")
        if sametypesequence:
            return self._get_entry_sametypesequence(size)
        else:
            return self._get_entry(size)

    def _get_entry(self, size):
        result = dict()
        read_size = 0
        start_offset = self._offset
        while read_size < size:
            type_identifier = struct.unpack("!c")
            if type_identifier in "mlgtxykwhnr":
                result[type_identifier] = self._get_entry_field_null_trail()
            else:
                result[type_identifier] = self._get_entry_field_size()
            read_size = self._offset - start_offset
        return result
        
    def _get_entry_sametypesequence(self, size):
        start_offset = self._offset
        result = dict()
        sametypesequence = self._dict_ifo.get_ifo("sametypesequence")
        for k in range(0, len(sametypesequence)):
            if sametypesequence[k] in "mlgtxykwhnr":
                if k == len(sametypesequence)-1:
                    result[sametypesequence[k]] = self._get_entry_field_size(size - (self._offset - start_offset))
                else:
                    result[sametypesequence[k]] = self._get_entry_field_null_trail()
            elif sametypesequence[k] in "WP":
                if k == len(sametypesequence)-1:
                    result[sametypesequence[k]] = self._get_entry_field_size(size - (self._offset - start_offset))
                else:
                    result[sametypesequence[k]] = self._get_entry_field_size()
        return result

    def end(self, target, start) :
        while True :
            if self.db["_dict_file"][start] == target :
                 return start
            start += 1

    def _get_entry_field_null_trail(self):
        end = self.end("\0", self._offset)
        result = "".join(self.db["_dict_file"][self._offset:end])
        self._offset = end+1
        return result
        
    def _get_entry_field_size(self, size = None):
        if size == None:
            size = struct.unpack("!I", "".join(self.db["_dict_file"][self._offset:self._offset+4]))
            self._offset += 4
        result = "".join(self.db["_dict_file"][self._offset:self._offset+size])
        self._offset += size
        return result
        
def load_dictionary(db, files):

    ifo_reader = IfoFileReader(db, files["ifo_file"])
    idx_reader = IdxFileReader(db, files["idx_file"])
    return DictFileReader(db, files["dict_file"], ifo_reader, idx_reader, True)

def lookup(d, uni) :
    result = d.get_dict_by_word(uni)

    if result and len(result) > 0 :
        #print str(result)
        for trans in result :
            if 'm' in trans :
                print str(trans['m'])
            else :
                print "No 'm' index in translation: " + str(trans)
        '''
        '''
    else :
        print ["No translation available."]

if __name__ == "__main__":
    #files = dict(dict_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.dict.dz", idx_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.idx", ifo_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.ifo")
    #files = dict(ifo_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.ifo", idx_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.idx", dict_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.dict.dz")

    files = dict(dict_file = "stardict-lazyworm-ec-2.4.2/lazyworm-ec.dict.dz", idx_file = "stardict-lazyworm-ec-2.4.2/lazyworm-ec.idx", ifo_file = "stardict-lazyworm-ec-2.4.2/lazyworm-ec.ifo")

    if len(sys.argv) < 2 :
        print "Need english."
        exit(1)

    d = load_dictionary(files)

    words = sys.argv[1].split(" ")
    for word in words :
        print "Translating: " + word + "\n=============\n"
        uni = word.decode("utf-8")
        lookup(d, uni)

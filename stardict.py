#!/usr/bin/python
# coding: utf-8
from gzip import open as gzip_open
from os import SEEK_SET
from os.path import getsize 
from common import *
from time import time
from struct import unpack

# This is a re-write of the stardict dictionary parser
# so that instead of loading all the dictionaries into
# memory we only load them from files when we need them.
# This makes the dictionaries have no footprint inside
# a mobile application.

# The IDX files, however had to be ported to a Btree-style
# structure because they cannot be indexed directly,
# so we were forced to switch over to sqlite.

# This makes the original stardicts not so portable,
# but the conversion is only a one-time operation,
# so it's not a big deal. (It also balloons the original
# dictionary files to many megabytes, but that's the
# price of saving the extra RAM while getting the
# same performance).

def get_end(fh, target, start) :
    fh.seek(start, SEEK_SET)
    while True :
        b = fh.read(1)
        if b == target :
             return start
        start += 1

def get_entry(fh, start, stop) :
    entry = []
    fh.seek(start, SEEK_SET)
    for idx in range(start, stop) :
        entry.append(fh.read(1))
    return entry

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

        s = self.db["_word_idx"].select()
        rs = s.execute()
        result = rs.fetchone()

        if result is None :
            self._size = getsize(filename)
            if compressed:
                self.fh = gzip_open(filename, "rb")
            else:
                self.fh = open(filename, "rb")

            self._index = 0
            self._index_offset_bits = index_offset_bits
            #self.db["_word_idx"] = OOBTree()
            #self.db["_index_idx"] = OOBTree()
            trans = self.db["conn"].begin()
            for word_str, word_data_offset, word_data_size, index in self:
                #self.db["_index_idx"][self._index - 1] = (word_str, word_data_offset, word_data_size)

                i = self.db["_index_idx"].insert().values(idx = self._index - 1,
                          word_str = word_str.decode("utf-8"),
                          word_data_offset = word_data_offset,
                          word_data_size = word_data_size)

                self.db["conn"].execute(i)
                #if word_str not in self.db["_word_idx"]:
                #    self.db["_word_idx"][word_str] = []
                #self.db["_word_idx"][word_str].append(self._index - 1)
                s = self.db["_word_idx"].select().where(self.db["_word_idx"].c.word_str == word_str.decode("utf-8"))
                rs = s.execute()
                result = rs.fetchone()
                t = time()
                if result is None :
                    i = self.db["_word_idx"].insert().values(word_str = word_str.decode("utf-8"), idx = str([]))
                    self.db["conn"].execute(i)
                    rs = s.execute()
                    result = rs.fetchone()

                newlist = eval(result[1])
                newlist.append(self._index - 1)
                j = self.db["_word_idx"].update().values(idx = str(newlist)).where(self.db["_word_idx"].c.word_str == word_str.decode("utf-8"))

                self.db["conn"].execute(j)

            trans.commit()
            del self._index_offset_bits

            mdebug("There were " + str(self._offset) + " total words.")

    def __iter__(self):
        """Define the iterator interface.
        
        """
        return self

    def next(self):
        """Define the iterator interface.
        
        """
        if self._offset == self._size:
            raise StopIteration
        word_data_offset = 0
        word_data_size = 0
        end = get_end(self.fh, "\0", self._offset)
        word_str = b"".join(get_entry(self.fh, self._offset, end))
        self._offset = end+1
        if self._index_offset_bits == 64:
            word_data_offset, = unpack("!I", b"".join(get_entry(self.fh, self._offset, self._offset+8)))
            self._offset += 8
        elif self._index_offset_bits == 32:
            word_data_offset, = unpack("!I", b"".join(get_entry(self.fh, self._offset, self._offset+4)))
            self._offset += 4
        else:
            raise ValueError
        word_data_size, = unpack("!I", b"".join(get_entry(self.fh, self._offset, self._offset+4)))
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
        if number >= self._index :
            raise IndexError("Index out of range! Acessing the {:d} index but totally {:d}".format(number, self._index))

        s = self.db["_index_idx"].select().where(self.db["_index_idx"].c.idx == number)
        rs = s.execute()
        result = rs.fetchone()
        mdebug("Result: " + str(result))
        return [result[1], result[2], result[3]]

    def get_index_by_word(self, word_str):
        """Get index infomation of a specified word entry.
        
        Arguments:
        - `word_str`: name of word entry.
        Return:
        Index infomation corresponding to the specified word if exists, otherwise False.
        The index infomation returned is a list of tuples, in form of [(word_data_offset, word_data_size) ...]
        """
        s = self.db["_word_idx"].select().where(self.db["_word_idx"].c.word_str == word_str.decode("utf-8"))
        rs = s.execute()
        result = rs.fetchone()
        mdebug("Result for " + word_str + ": " + str(result))
        if result is None :
            return False
        wlist = eval(result[1])
        index = list()
        for n in wlist :
            s = self.db["_index_idx"].select().where(self.db["_index_idx"].c.idx == n)
            rs = s.execute()
            result = rs.fetchone()
            mdebug("Result index for " + word_str + ": " + str(result))
            if result is None :
                mwarn("Uh Oh: This isn't supposed to happen, is it? English lookup " + word_str + " returns no index at number " + str(n)) 
                return False
            index.append([result[2], result[3]])
        return index

class DictFileReader(object):
    """Read the .dict file, store the data in memory for querying.
    """
    
    def __init__(self, filename, dict_ifo, dict_index, compressed = False):
        """Constructor.
        
        Arguments:
        - `filename`: filename of .dict file.
        - `dict_ifo`: IfoFileReader object.
        - `dict_index`: IdxFileReader object.
        """
        self._dict_ifo = dict_ifo
        self._dict_index = dict_index
        self._compressed = compressed
        self._offset = 0

        if self._compressed:
            self.fh = gzip_open(filename, "rb")
        else:
            self.fh = open(filename, "rb")

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
            type_identifier = unpack("!c")
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

    def _get_entry_field_null_trail(self):
        end = end(self.fh, "\0", self._offset)
        entry = get_entry(self.fh, self._offset, end)
        result = "".join(entry)
        self._offset = end+1
        return result
        
    def _get_entry_field_size(self, size = None):
        if size == None:
            size = unpack("!I", "".join(get_entry(self.fh, self._offset, self._offset+4)))
            self._offset += 4
        result = "".join(get_entry(self.fh, self._offset, self._offset+size))
        self._offset += size
        return result
        
def load_dictionary(db, files):

    ifo_reader = IfoFileReader(db, files["ifo_file"])
    idx_reader = IdxFileReader(db, files["idx_file"])
    return DictFileReader(files["dict_file"], ifo_reader, idx_reader)

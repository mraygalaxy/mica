#!/usr/bin/env bash

# Better way of getting absolute path instead of relative path
if [ $0 != "-bash" ] ; then
        pushd `dirname "$0"` 2>&1 > /dev/null
fi

dir=$(pwd)

if [ $0 != "-bash" ] ; then
        popd 2>&1 > /dev/null
fi

pushd $dir/../res

for lang in zh py es ; do
    echo "want to regenerate messages for language: $lang file $file"

    if [ ! -e messages_${lang}.po ] ; then
        echo "First time generation of language: $lang"
	xgettext --omit-header --no-location --package-name=MICA --package-version="beta" --copyright-holder="Michael R. Hines michael@hinespot.com" $dir/../*.py
        mv messages.po messages_${lang}.po
    fi

    if [ -e messages_${lang}.po ] ; then
	cp -f messages_${lang}.po messages_${lang}.po.bak
	mv -f messages_${lang}.mo messages_${lang}.mo.bak
	mv -f messages_${lang}.po messages_dirty.po
        cat messages_dirty.po | grep -v "^#\." | grep -v "^#:" > messages.po
	rm -f messages_dirty.po
	xgettext --add-comments --omit-header --no-location -j $dir/../*.py
	mv -f messages.po messages_${lang}.po
	msgfmt -o messages_${lang}.mo messages_${lang}.po 
    fi
done

popd

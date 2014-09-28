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

for lang in "zh" ; do
    echo "want to regenerate messages for language: $lang file $file"

    if [ -e messages_${lang}.po ] ; then
	cp -f messages_${lang}.po messages_${lang}.po.bak
	mv -f messages_${lang}.mo messages_${lang}.mo.bak
	mv -f messages_${lang}.po messages.po
	xgettext -j $dir/../*.py
	mv -f messages.po messages_${lang}.po
	msgfmt -o messages_${lang}.mo messages_${lang}.po 
    fi
done

popd

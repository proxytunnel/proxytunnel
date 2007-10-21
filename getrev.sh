#!/bin/sh

REV=`svn info . 2> /dev/null | grep '^Revision' | awk '{print $2}'`
if [ "x$REV" = "x" ] ; then
	echo "0"
else
	echo $REV
fi
exit 0;

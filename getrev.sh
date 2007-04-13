#!/bin/sh
svn info . | grep '^Revision' | awk '{print $2}'

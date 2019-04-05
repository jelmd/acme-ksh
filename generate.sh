#!/bin/ksh93

FILE=${ mktemp foo.XXXXXX ; }
[[ -z ${FILE} ]] && exit 1
trap "rm -f ${FILE}" EXIT

while read -r -A L ; do
	[[ ${L} == '#include' && ${L[1]:0:1} == '"' ]] || continue
	F="${L[1]}"
	FN="${F:1:${#F}-2}"
	print "/^#include ${F//\//\\\/}/ {\nr ${FN}\nd\n}" >>${FILE}
	[[ -e ${FN} ]] || print -u2 "Include file '$FN' does not exist!"
done <"$1"
if [[ -s ${FILE} ]]; then
	sed -f ${FILE} "$1" || { print 'sed file:\n' ; cat ${FILE} ; }
else
	cat "$1"
fi

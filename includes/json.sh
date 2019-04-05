#!/bin/ksh93

# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License") version 1.1!
# You may not use this file except in compliance with the License.
#
# See LICENSE.txt included in this distribution for the specific
# language governing permissions and limitations under the License.
#
# Copyright 2019 Jens Elkner (jel+json-src@cs.ovgu.de)

#typeset JSON_LIB=${.sh.file}
typeset RUN_SCRIPT=$( cd ${ dirname $0 }; print -n "$PWD/${ basename $0; }"; )

if [[ ${JSON_LIB} == ${RUN_SCRIPT} ]]; then
# SOBP
typeset -r FPROG=${.sh.file}
typeset -r PROG=${FPROG##*/}

typeset -r VERSION='1.0' LIC='[-?'"${VERSION}"' ]
[-copyright?Copyright (c) 2017 Jens Elkner. All rights reserved.]
[-license?CDDL 1.0]'

for H in log.kshlib man.kshlib ; do
	X=${SDIR}/$H
	[[ -r $X ]] && . $X && continue
	X=${ whence $H; }
	[[ -z $X ]] && print "$H not found - exiting." && exit 1
	. $X
done
unset H

function showUsage {
	typeset WHAT="$1" X='--man'
	[[ -z ${WHAT} ]] && WHAT='MAIN' && X='-?'
	getopts -a "${PROG}" "${ print ${Man.FUNC[${WHAT}]}; }" OPT $X
}
# EOBP
fi

### JSON impl. start ###
alias json='typeset -uli'
alias json_t='typeset -usi'

#typeset -h '[-?'"${VERSION}"' ]
#[-copyright?Copyright (c) 2017 Jens Elkner. All rights reserved.]
#[-license?CDDL 1.0]
#[+NAME?JSON_t - a simple JSON object container]
#[+DESCRIPTION?which allows one to create and set the value of an JSON object as well as to dump JSON objects in JSON format.]
#' JSON_t
typeset -T JSON_t=(
	# unique JSON value ID
	typeset -usih 'private. Do not touch' _OID_FALSE=1
	typeset -usih 'private. Do not touch' _OID_TRUE=2
	typeset -usih 'private. Do not touch' _OID_NULL=3

	typeset -ulih 'private. Do not touch' _OID=10		# first free OID
	typeset -S _OID		# share to avoid problems

	function _nextId {
		typeset -n V=$1
		(( _._OID++ ))
		V=${_._OID}
	}
	typeset -fh 'private. Do not touch.' _nextId

	# JSON types
	typeset -usih 'private. Do not touch' _OBJ=1
	typeset -usih 'private. Do not touch' _ARR=2
	typeset -usih 'private. Do not touch' _NUM=3
	typeset -usih 'private. Do not touch' _STR=4
	typeset -usih 'private. Do not touch' _TRUE=5
	typeset -usih 'private. Do not touch' _FALSE=6
	typeset -usih 'private. Do not touch' _NULL=7
	typeset -usih 'private. Do not touch' -A _ID2TYP

	create() {
		_._ID2TYP["_${_._OID_FALSE}"]=${_._FALSE}
		_._ID2TYP["_${_._OID_TRUE}"]=${_._TRUE}
		_._ID2TYP["_${_._OID_NULL}"]=${_._NULL}
		typeset -r _._OID_FALSE _._OID_TRUE _._OID_NULL \
			_._OBJ _._ARR _._NUM _._STR _._TRUE _._FALSE _._NULL
	}
	typeset -fh 'private. Do not touch.' create

	function isObject { (( ${_._ID2TYP["_$1"]} == _._OBJ )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON object.' isObject
	function isArray { (( ${_._ID2TYP["_$1"]} == _._ARR )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON array.' isArray
	function isNumber { (( ${_._ID2TYP["_$1"]} == _._NUM )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON number value.' isNumber
	function isString { (( ${_._ID2TYP["_$1"]} == _._STR )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON string value.' isString
	function isTrue { (( $1 == _._OID_TRUE )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON true value.' isTrue
	function isFalse { (( $1 == _._OID_FALSE )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON false value.' isFalse
	function isNull { (( $1 == _._OID_NULL )) ; }
	typeset -fh 'Check, whether the given JSON component ID (arg1) is the ID of a JSON null value.' isNull
	function getType {
		typeset X=${_._ID2TYP["_$1"]}; [[ -z $X ]] && X=0
		[[ -n $2 ]] && typeset -n R=$2 && R=$X
		return $X
	}
	typeset -fh 'Get the type ID of an JSON component (numeric value). Arg1 .. ID of the JSON component to lookup; Arg2 .. where to put the result (optional). On success the exit code is > 0 and denotes the type ID.' getType

	# Data stores
	typeset -Ah 'private. Do not touch' _ID2STR
	typeset -Ah 'private. Do not touch' _ID2NUM
	typeset -Ah 'private. Do not touch' _ID2ARR
	#typeset -Aulih 'private. Do not touch' _ID2OBJ
	typeset -Auli _ID2OBJ

	function reset {
		unset _._ID2STR ; typeset -Ah 'private. Do not touch' _._ID2STR
		unset _._ID2NUM ; typeset -Ah 'private. Do not touch' _._ID2NUM
		unset _._ID2ARR ; typeset -Ah 'private. Do not touch' _._ID2ARR
		unset _._ID2OBJ ; typeset -Aulih 'private. Do not touch' _._ID2OBJ
		unset _._ID2TYP ; typeset -Ausih 'private. Do not touch' _._ID2TYP
		_._ID2TYP["_${_._OID_FALSE}"]=${_._FALSE}
		_._ID2TYP["_${_._OID_TRUE}"]=${_._TRUE}
		_._ID2TYP["_${_._OID_NULL}"]=${_._NULL}
	}
	typeset -fh 'Resets the state of this instance and cleanup all IDs and associations wrt. created objects, their IDs, values and types.' reset

	function newObject {
		json N ; _._nextId N ; _._ID2TYP["_$N"]=${_._OBJ}
		# the () is important! Otherwise a [0]=$RANDOM entry gets injected by
		# the shell, which in turn would break toString()
		typeset -A _._ID2OBJ["_$N"]=()
		[[ -n $1 ]] && typeset -n R=$1 && R=$N
		return ${_._OBJ}
	}
	typeset -fh 'Creates a new JSON object. If a vname (arg1) is given, the JSON component ID gets assigned to it. The exit code of this function is the typeID of the new JSON component.' newObject
	function newArray {
		json N ; _._nextId N ; _._ID2TYP["_$N"]=${_._ARR}
		[[ -n $1 ]] && typeset -n R=$1 && R=$N
		return ${_._ARR}
	}
	typeset -fh 'Creates a new JSON array. If a vname (arg1) is given, the JSON component ID gets assigned to it. The exit code of this function is the typeID of the new JSON component.' newArray
	function newString {
		json N ; _._nextId N ; _._ID2TYP["_$N"]=${_._STR}
		[[ -n $1 ]] && typeset -n R=$1 && R=$N
		[[ -n $2 ]] && _._ID2STR["_$N"]="$2"
		return ${_._STR}
	}
	typeset -fh 'Creates a new JSON string. If a vname (arg1) is given, the JSON component ID gets assigned to it. If a string (arg2) is given, this string gets assigned to this component. The exit code of this function is the typeID of the new JSON component.' newString
	function newNumber {
		json N ; _._nextId N ; _._ID2TYP["_$N"]=${_._NUM}
		[[ -n $1 ]] && typeset -n R=$1 && R=$N
		[[ -n $2 ]] && _._ID2NUM["_$N"]="$2"
		return ${_._NUM}
	}
	typeset -fh 'Creates a new JSON number. If a vname (arg1) is given, the JSON component ID gets assigned to it. If a string (arg2) is given, this string gets assigned to this component - no validation is done, whether the value is ECMA 404 conform. The exit code of this function is the typeID of the new JSON component.' newNumber
	function newTrue {
		[[ -n $1 ]] && typeset -n R=$1 && R=${_._OID_TRUE}
		return ${_._OID_TRUE}
	}
	typeset -fh 'Get the JSON true value. If a vname (arg1) is given, its JSON component ID gets assigned to it. The exit code of this function is the ID of the new JSON component as well.' newTrue
	function newFalse {
		[[ -n $1 ]] && typeset -n R=$1 && R=${_._OID_FALSE}
		return ${_._OID_FALSE}
	}
	typeset -fh 'Get the JSON false value. If a vname (arg1) is given, its JSON component ID gets assigned to it. The exit code of this function is the ID of the new JSON component as well.' newFalse
	function newNull {
		[[ -n $1 ]] && typeset -n R=$1 && R=${_._OID_NULL}
		return ${_._OID_NULL}
	}
	typeset -fh 'Get the JSON null value. If a vname (arg1) is given, its JSON component ID gets assigned to it. The exit code of this function is the ID of the new JSON component as well.' newNull

	function getPropNames {
		[[ -z $1 ]] && return 1
		[[ -z $2 ]] && return 2
		typeset -n RES=$2
		RES=${!_._ID2OBJ["_$1"][@]}
	}
	typeset -fh 'Get the property names of the JSON object with the given ID (arg1). A vname (arg2) is required, to be able to store all property names as a simple string separated by a single space. Exit code is 0 on success, != 0 otherwise.' getPropNames

	function getVal {
		[[ -z $1 ]] && return 1		# OID required
		[[ -z $2 ]] && return 2		# where to store required
		typeset -n RES=$2
		json_t T=${_._ID2TYP["_$1"]}
		if (( T == _._OBJ )) ; then
			typeset X PROPS
			_.getPropNames $1 PROPS
			for X in ${PROPS} ; do
				RES["$X"]=${_._ID2OBJ["_$1"]["$X"]}
			done
		elif (( T == _._ARR )) ; then
			RES="${_._ID2ARR[_$1]}"
		elif (( T == _._STR )) ; then
			RES="${_._ID2STR[_$1]}"
		elif (( T == _._NUM )) ; then
			RES="${_._ID2NUM[_$1]}"
		elif (( T == _._TRUE )) ; then
			RES='true'
		elif (( T == _._FALSE )) ; then
			RES='false'
		elif (( T == _._NULL )) ; then
			RES='null'
		else
			RES=
			return 2
		fi
		return 0
	}
	typeset -fh 'Get the value of the JSON component with the given ID (arg1). The vname (arg2) is required to be able to store the component'"'"'s value. For JSON objects it should be the name of an associative array and will contain the property name as key and the related JSON component ID as value. For a JSON array a simple string gets returned, which contains a space separated ID list of JSON components belonging to this array. For all other types its scalar value gets returned. Exit code is 0 on success (component with the given ID exists and has a valid type), != 0 otherwise.' getVal

	function setVal {
		[[ -z $1 ]] && return 1		# OID required
		[[ -z $2 ]] && return 0		# nothing to add
		json OID=$1 N
		json_t T=${_._ID2TYP["_${OID}"]}
		typeset IDA S

		(( T )) || return 2		# invalid OID
		shift

		if (( T == _._OBJ )) ; then
			while [[ -n $1 ]]; do
				N=$2
				[[ -z ${_._ID2TYP["_$N"]} ]] && return 4	# unknown type
				_._ID2OBJ["_${OID}"]["$1"]=$N
				shift 2
			done
		elif (( T == _._ARR )) ; then
			for N ; do
				[[ -z ${_._ID2TYP["_$N"]} ]] && return 5	# unknown type
				IDA+=" $N"
			done
			_._ID2ARR["_${OID}"]="${IDA}"
		elif (( T == _._STR )) ; then
			for S ; do
				IDA+="$S"
			done
			_._ID2STR["_${OID}"]="${IDA}"
		elif (( T == _._NUM )) ; then
			[[ -n $2 ]] && return 6
			_._ID2NUM["_${OID}"]="$1"	# basically its a string
		else
			return 2
		fi
		return 0
	}
	typeset -fh 'Set the value of the JSON component with the given ID (arg1) to the argument[s]] which follow: For a JSON object the arguments should be the literal property name (arg2n) and the JSON component ID (arg2n+1) of the property value. For a JSON array the arguments should be the JSON component IDs of its values. For a JSON string all arguments gets pasted literally together without any delimiter and the resulting string gets assigned to it. For a JSON number only arg2 gets assigned to it as is - no validation wrt. ECMA 404 conformance will be made. Because all other JSON components are constants, setting them results into an error, i.e. an exit code != 0. An exit code of 0 gets returned, if the given argument[s]] have been assigned as described.' setVal

	function str2json {
		[[ -z $2  ]] && return 0				# no string to convert
		typeset -n BUF=$1 || return 1			# no write buffer
		typeset S=$2 C T='"'
		for (( I=0; I < ${#S}; I++ )) ; do
			C=${S:I:1}
			# control characters
			if [[ $C < ' ' ]]; then
				# specials
				if [[ $C == $'\n' ]]; then
					T+='\n'
				elif [[ $C == $'\t' ]]; then
					T+='\t'
				elif [[ $C == $'\r' ]]; then
					T+='\r'
				elif [[ $C == $'\f' ]]; then
					T+='\f'
				elif [[ $C == $'\b' ]]; then
					T+='\b'
				# others
				elif [[ $C == $'\a' ]]; then
					T+='\u0007'
				elif [[ $C == $'\E' ]]; then
					T+='\u0027'
				else
					T+=${ printf '\u%04x' "'$C'" ; }	# unicode  OR:
					#C=${ printf '%q' "$C"; }	# e.g. C == $'\x{2}([0-9a-f])'
					#T+='\u00'"${C:4:2}"
				fi
			# " \ /
			elif [[ $C == '"' ]]; then
				T+='\"'
			elif [[ $C == '\' ]]; then
				T+='\\'
			elif [[ $C == '/' ]]; then
					T+='\/'
			else
				T+="$C"
			fi
		done
		BUF+="$T\""
	}
	typeset -fh 'Converts a string into its JSON representation by enclosing it into double quotes and escaping all characters as specified by ECMA 404. The converted string gets append to the value of the given vname (arg1). Arg2 is used as the string to convert. To print out the result one should use the -r (raw) option of print/printf, otherwise escaped characters get intepreted and thus implicit converted back to its original value (and uni code sequences get trashed).' str2json

	function toString {
		[[ -z $1 ]] && return 2		# OID
		[[ -z $2 ]] && return 1		# dest buffer required
		typeset -n BUF=$2
		typeset X S V PNAME
		json OID=$1
		json_t T

		_.getType ${OID} T && return 3	# prop value type unknown
		if (( T == _._OBJ )); then
			typeset -A MAP
			JSON.getVal ${OID} MAP
			S=
			set -s -- "${!MAP[@]}"		# sort it to have a stable output
			for PNAME ; do
				V=
				_.str2json V "${PNAME}"
				[[ -z $V ]] && continue
				S+="${V}:"
				_.toString ${MAP[${PNAME}]} S || return 5
				S+=','
			done
			S="{${S%,}}"
		elif (( T == _._ARR )); then
			typeset A=${_._ID2ARR["_${OID}"]}
			if [[ -n $A ]]; then
				for X in $A ; do
					V=
					_.toString $X V || return 6
					[[ -n $V ]] && S+=",$V"
				done
			fi
			S="[${S:1}]"
		elif (( T == _._NUM )); then
			_.getVal ${OID} S
		elif (( T == _._STR )); then
			_.str2json S "${_._ID2STR[_${OID}]}"
		elif (( T == _._TRUE )); then
			S='true'
		elif (( T == _._FALSE )); then
			S='false'
		elif (( T == _._NULL )); then
			S='null'
		fi
		BUF+="$S"
		return 0
	}
	typeset -fh 'Converts the JSON component with the given ID (arg1) to its JSON representation as specified by ECMA 404. Arg2 is required to store the result. On success the exit code is 0, a value != 0 otherwise. Note: Make sure you have read the "str2json" help as well to avoid surprises!' toString

	function toStringPretty {
		[[ -z $1 ]] && return 2		# OID
		[[ -z $2 ]] && return 1		# dest buffer required
		typeset -n BUF=$2
		typeset I X S V PNAME INDENT='    '
		[[ -n $3 ]] && typeset -n PREFIX=$3 || typeset PREFIX=
		[[ -n $4 ]] && INDENT="$4"
		json OID=$1
		json_t T

		_.getType ${OID} T && return 3	# prop value type unknown
		if (( T == _._OBJ )); then
			typeset -A MAP
			JSON.getVal ${OID} MAP
			S=
			set -s -- "${!MAP[@]}"		# sort it to have a stable output
			I="${PREFIX}${INDENT}"
			for PNAME ; do
				V=
				_.str2json V "${PNAME}"
				[[ -z $V ]] && continue
				S+="${I}${V}: "
				_.toStringPretty ${MAP[${PNAME}]} S I "${INDENT}" || return 5
				S+=',\n'
			done
			[[ -n $S ]] && S="{\n${S%,\\n}\n${PREFIX}}" || S='{ }'
		elif (( T == _._ARR )); then
			typeset A=${_._ID2ARR["_${OID}"]}
			I="${PREFIX}${INDENT}"
			if [[ -n $A ]]; then
				for X in $A ; do
					V=
					_.toStringPretty $X V I "${INDENT}" || return 6
					[[ -n $V ]] && S+=",\n${I}$V"
				done
			fi
			[[ -n $S ]] && S="[\n${S:3}\n${PREFIX}]"  || S='[ ]'
		elif (( T == _._NUM )); then
			_.getVal ${OID} S
		elif (( T == _._STR )); then
			_.str2json S "${_._ID2STR[_${OID}]}"
		elif (( T == _._TRUE )); then
			S='true'
		elif (( T == _._FALSE )); then
			S='false'
		elif (( T == _._NULL )); then
			S='null'
		fi
		BUF+="$S"
		return 0
	}
	typeset -fh 'Converts the JSON component with the given ID (arg1) to its JSON representation as specified by ECMA 404. Arg2 is required to store the result. If Arg3 is given, its value gets used as current indent prefix. If arg4 is given, its value gets append to the prefix for further indenting as needed. If not given, 4 spcaes in a row will be used. On success the exit code is 0, a value != 0 otherwise. Note: Make sure you have read the "str2json" help as well to avoid surprises!' toStringPretty
)

#typeset -h '[-?'"${VERSION}"' ]
#[-copyright?Copyright (c) 2017 Jens Elkner. All rights reserved.]
#[-license?CDDL 1.0]
#[+NAME?JSON_Parser_t - a simple parser for JSON formatted values.]
#[+DESCRIPTION?The JSON_Parser_t can be used to parse in JSON formatted values, i.e. JSON objects, arrays, strings, numbers as well as the JSON values true, false and null. The parser uses the JSON_t factory named "JSON" (global type) to register all encountered JSON components, their type, association and values.]
#' JSONP_t
typeset -T JSONP_t=(
	function isWS {
		integer C=$(("'$1'"))
		(( C == 32 || C == 10 || C == 9 || C == 13 ))
	}
	typeset -fh 'Check, whether the given character is whitespace character wrt. ECMA 404. Returns 1 if not, 0 otherwise.' isWS

	function readString {
		typeset -n VAL=$1 PUSH_BACK=$2
		typeset B T
		typeset -l UC
		typeset -i16 C
		while : ; do
			if [[ -n ${PUSH_BACK} ]]; then
				B="${PUSH_BACK:0:1}" PUSH_BACK=
			else
				read -N1 B || return 99
			fi
			[[ $B == '"' ]] && \
				return 0
			if [[ $B == '\' ]]; then
				read -N1 B || return 99
				[[ $B == '"' || $B == '\' || $B == '/' ]] && \
					VAL+="$B" && continue
				[[ $B == 'b' ]] && VAL+=$'\b' && continue
				[[ $B == 'f' ]] && VAL+=$'\f' && continue
				[[ $B == 'n' ]] && VAL+=$'\n' && continue
				[[ $B == 'r' ]] && VAL+=$'\r' && continue
				[[ $B == 't' ]] && VAL+=$'\t' && continue
				if [[ $B == 'u' ]]; then
					read -N4 T || return 99
					UC="$T"
					[[ ${UC} == {4}([0-9a-f]) ]] && \
						VAL+=${ printf "\u${UC}"; } && continue
					B+="$T"
				fi
				# actually not allowed but probably ok
				Log.fatal "Invalid escape sequence in string - got '${VAL}\\$B'"
				return 3
			fi
			[[ $B < ' ' ]] && Log.fatal "Parser error: Unexpected control" \
				"character in string - have '${VAL}' and 0x${C:3}." && return 4
			VAL+="$B"
		done
		Log.fatal "Parser error: unexpected end of string -" \
			"expected '\"'." # "''"
		return 4
	}
	typeset -fh 'Reads in a JSON string from stdin and stores the result into vname (arg1). It expects that its 1st character, i.e. a single double quote (") has been already read. If arg2 contains a character on function entry, its gets read and cleared before reading from stdin starts. Escaped special characters as described in ECMA 404 get converted back to its original. E.g. the 2 characters "\n" get converted into a single linefeed character (0x10) and append to the result. However, the three characters "\\n" get converted into the 2 characters "\n". On success (the end of string has been found, i.e. a single double quote) this function returns 0, a value != 0 otherwise.' readString

	function readDigits {
		typeset -n VAL=$1 PUSH_BACK=$2
		typeset B V=
		while : ; do
			if [[ -n ${PUSH_BACK} ]]; then
				B="${PUSH_BACK:0:1}" PUSH_BACK=
			elif !  read -N1 B ; then
				[[ -z $V ]] && return 99
				break
			fi
			[[ $B > '/' && $B < ':' ]] && V+="$B" && continue
			PUSH_BACK="$B"
			break
		done
		[[ -z $V ]] && return 1
		VAL+="$V"
		return 0
	}
	typeset -fh 'Reads in digits 0..9 until a non-diget gets encountered. This non-digit gets stored to the given vname (arg2) and all digits read so far get append to the given vname (arg1). If arg2 contains a character on function entry, it gets analyzed first, before reading from stdin starts. On success (at least one digit has been read) this function returns 0, a value != 0 otherwise.' readDigits

	function readNumber {
		typeset -n SELF=$1 PUSH_BACK=$2
		json NUM_OID
		typeset B N= D=
		SELF=0
		integer OK=0

		JSON.newNumber NUM_OID
		while : ; do
			if [[ -n ${PUSH_BACK} ]]; then
				B="${PUSH_BACK:0:1}" PUSH_BACK=
			else
				read -N1 B || return 99
			fi
			_.isWS "$B" && continue
			[[ $B == '+' || $B == '-' ]] && N="$B" && break
			[[ $B == [0-9] ]] && PUSH_BACK=$B && break
			Log.fatal "Parser error: invalid number - expected digit, or '+'," \
				"or '-' but got '$B'"
			return 1
		done
		_.readDigits D PUSH_BACK || return 2
		N+="$D"
		if [[ -n ${PUSH_BACK} ]]; then
			B="${PUSH_BACK}" PUSH_BACK=
		elif ! read -N1 B ; then
			# same thing like at the end - shells have no goto
			[[ -z $N ]] && return 6
			(( JSON_DEBUG )) && print -u2 "Number[${NUM_OID}]:  $N"
			JSON.setVal ${NUM_OID} "$N"
			SELF=${NUM_OID}
			return 0
		fi
		if [[ $B == '.' ]]; then
			D=
			_.readDigits D PUSH_BACK || return 3
			N+="$D"
		else
			PUSH_BACK=$B
		fi
		if [[ -n ${PUSH_BACK} ]]; then
			B="${PUSH_BACK}" PUSH_BACK=
		elif ! read -N1 B ; then
			# same thing like at the end - shells have no goto
			[[ -z $N ]] && return 6
			(( JSON_DEBUG )) && print -u2 "Number[${NUM_OID}]:  $N"
			JSON.setVal ${NUM_OID} "$N"
			SELF=${NUM_OID}
			return 0
		fi
		PUSH_BACK=
		if [[ $B == 'e' || $B == 'E' ]]; then
			N+="$B"
			read -N1 B || return 99
			if [[ $B == '+' || $B == '-' ]]; then
				N+="$B"
			elif [[ $B == [0-9] ]]; then
				PUSH_BACK=$B
			else
				Log.fatal "Parser error: invalid number - expected digit," \
					"or '+', or '-' after exponent sign but got '$B'"
				return 4
			fi
			D=
			_.readDigits D PUSH_BACK || return 5
			N+="$D"
		else
			PUSH_BACK=$B
		fi
		[[ -z $N ]] && return 6
		(( JSON_DEBUG )) && print -u2 "Number[${NUM_OID}]:  $N"
		JSON.setVal ${NUM_OID} "$N"
		SELF=${NUM_OID}
		return 0
	}
	typeset -fh 'Reads in a JSON formatted number from stdin, registers it with "JSON" factory and stores the ID of the created JSON component into the given vname (arg1). If arg2 contains a character on function entry, it gets read first, before the function starts reading from stdin. On return it may contain a character: the one which does belong to something else, but not to a JSON formatted number. On success (a JSON number could be read) this function returns 0, a value != 0 otherwise.' readNumber

	function readObject {
		typeset -n SELF=$1 PUSH_BACK=$2
		json OBJ_OID OID
		typeset PNAME
		typeset -a ARGS

		SELF=0
		JSON.newObject OBJ_OID
		(( JSON_DEBUG )) && print -u2 "Reading Object ${OBJ_OID} ..."
		while : ; do
			if [[ -n ${PUSH_BACK} ]]; then
				B="${PUSH_BACK:0:1}" PUSH_BACK=
			else
				read -N1 B || return 99
			fi
			[[ $B == '}' ]] && break
			_.isWS "$B" && continue
			if [[ $B == '"' ]]; then
				PNAME=
				_.readString PNAME PUSH_BACK || return 1
				[[ -z ${PNAME} ]] && return 1	# not allowed
				(( JSON_DEBUG )) && print -u2 "Key:  '${PNAME}'"
			else
				Log.fatal "Parser error: expected '\"' (start of property" \
					" name) bot got '$B'."
				return 2
			fi
			while : ; do
				read -N1 B || return 99
				_.isWS "$B" && continue
				[[ $B == ':' ]] && break
				Log.fatal "Parser error: expected ':' after property name" \
					"but got '$B'."
				return 3
			done
			_.readValue OID PUSH_BACK || return 4
			ARGS+=( "${PNAME}" ${OID} )
			while : ; do
				if [[ -n ${PUSH_BACK} ]]; then
					B="${PUSH_BACK}" PUSH_BACK=
				else
					read -N1 B || return 99
				fi
				_.isWS "$B" && continue
				[[ $B == ',' ]] && break
				[[ $B == '}' ]] && break 2
				Log.fatal "Parser error: expected whitespace, or '}' after" \
					"property value bot got '$B'."
				return 5
			done
		done
		(( JSON_DEBUG )) && print -u2 "Object[${OBJ_OID}]:  ${ARGS[@]}\n"
		JSON.setVal ${OBJ_OID} "${ARGS[@]}"
		SELF=${OBJ_OID}
		return 0
	}
	typeset -fh 'Reads in a JSON formatted object from stdin, registers it incl. all its properties and values with the "JSON" factory and stores the ID of the created JSON component into the given vname (arg1). It expects that its 1st character, i.e. a opening curly brace ({) has been already read. If arg2 contains a character on function entry, it gets read and cleared before reading from stdin starts. On success (a full JSON object including its closing curly brace (}) has been read) this function returns 0, a value != 0 otherwise.' readObject

	function readArray {
		typeset -n SELF=$1 PUSH_BACK=$2
		json ARR_OID OID
		typeset ARGS

		SELF=0
		JSON.newArray ARR_OID
		(( JSON_DEBUG )) && print -u2 "Reading Array ${ARR_OID} ..."
		while : ; do
			if [[ -n ${PUSH_BACK} ]]; then
				B="${PUSH_BACK}" PUSH_BACK=
			else
				read -N1 B || return 99
			fi
			[[ $B == ']' ]] && break
			_.isWS "$B" && continue
			PUSH_BACK="$B"
			_.readValue OID PUSH_BACK || return 2
			ARGS+=" ${OID}"
			while : ; do
				if [[ -n ${PUSH_BACK} ]]; then
					B="${PUSH_BACK}" PUSH_BACK=
				else
					read -N1 B || return 99
				fi
				_.isWS "$B" && continue
				[[ $B == ',' ]] && break
				[[ $B == ']' ]] && break 2
				Log.fatal "Parser error: expected whitespace or ']' after" \
					"property value bot got '$B'."
				return 1
			done
		done
		(( JSON_DEBUG )) && print -u2 "Array[${ARR_OID}]:  ${ARGS}"
		JSON.setVal ${ARR_OID} ${ARGS}
		SELF=${ARR_OID}
		return 0
	}
	typeset -fh 'Reads in a JSON formatted array from stdin, registers it incl. all its values with the "JSON" factory and stores the ID of the created JSON component into the given vname (arg1). It expects that its 1st character, i.e. a opening bracket ([) has been already read. If arg2 contains a character on function entry, it gets read and cleared before reading from stdin starts. On success (a full JSON array including its closing bracket (]]) has been read) this function returns 0, a value != 0 otherwise.' readArray

	function readValue {
		typeset -n VAL_OID=$1 PUSHED_BACK="$2"
		json OID=0
		typeset B S

		VAL_OID=0
		while : ; do
			if [[ -n ${PUSHED_BACK} ]]; then
				B="${PUSHED_BACK:0:1}" PUSHED_BACK=
			else
				read -N1 B || return 98
			fi
			_.isWS "$B" && continue
			if [[ $B == '{' ]]; then
				_.readObject OID PUSHED_BACK && break || return 1
			elif [[ $B == '[' ]]; then
				_.readArray OID PUSHED_BACK && break || return 2
			elif [[ $B == '"' ]]; then
				S=
				_.readString S PUSHED_BACK || return 3
				JSON.newString OID "$S"
				(( JSON_DEBUG )) && print -u2 "String[${OID}]:  '$S'"
			elif [[ $B == 't' ]]; then
				if read -N3 B  && [[ $B == 'rue' ]] ; then
					JSON.newTrue OID && break
				else
					Log.fatal 'Parser errror: Unable to read JSON value -' \
						"expected boolean value 'true' but got 't$B'."
					return 4
				fi
			elif [[ $B == 'f' ]]; then
				if read -N4 B  && [[ $B == 'alse' ]] ; then
					JSON.newFalse OID && break
				else
					Log.fatal 'Parser errror: Unable to read JSON value -' \
						"expected boolean value 'false' but got 'f$B'."
					return 5
				fi
			elif [[ $B == 'n' ]]; then
				if read -N3 B  && [[ $B == 'ull' ]] ; then
					JSON.newNull OID && break
				else
					Log.fatal 'Parser errror: Unable to read JSON value -' \
						"expected 'null' but got 'n$B'."
					return 6
				fi
			elif [[ $B == '-' || $B == [0-9] ]]; then
				PUSHED_BACK=$B
				_.readNumber OID PUSHED_BACK && break || return 7
			else
				Log.fatal "Parser error: unexpected char '$B'"
				PUSHED_BACK=$B
				return 7
			fi
			break
		done
		VAL_OID=${OID}
		return 0;
	}
	typeset -fh 'Reads in a JSON formatted value from stdin, registers it incl. all its sub-components with the "JSON" factory and stores the ID of the created JSON component into the given vname (arg1). If arg2 (vname required) contains a character on function entry, it gets read and cleared before reading from stdin starts. On success (a JSON value has been read) this function returns 0, a value != 0 otherwise.' readValue
)

JSON_t JSON
JSONP_t JSONP

### JSON impl. stop ###

if [[ ${JSON_LIB} == ${RUN_SCRIPT} ]]; then

function doMain {
	[[ -z $1 ]] && showUsage MAIN && exit 1

	json VAL
	typeset S PUSH_BACK=
	integer RES

	while : ; do
		S=
		Log.info "Scanning next value in $1 ..."
		JSONP.readValue VAL PUSH_BACK || { Log.fatal "failed with $?"; break ; }
		Log.info "done - ID ${VAL}. Converting to JSON string ..."
		if (( COMPACT )); then
			JSON.toString ${VAL} S
		else
			JSON.toStringPretty ${VAL} S
		fi
		(( $? == 0 )) && Log.info "got: " || Log.fatal "failed: "
		print "$S"
		JSON.reset
	done <$1
	Log.info "done."
}

Man.addFunc MAIN '' '[+NAME?'"${PROG}"' - JSON encoder/decoder]
[+DESCRIPTION?A simple implementation of an ECMA 404 compliant JSON parser/encoder. Right now it reads in the given JSON file and finally prints out, what it got in JSON format.]
[h:help?Print this help and exit immediately.]
[F:functions?Print out a list of all defined functions and exit immediately. Just invokes the \btypeset +f\b builtin.]
[H:usage]:[function?Show the usage information for the given function if available and exit immediately. As long as not explicitly mentioned, the return value of each function is 0 on success and != 0 otherwise. See also option \b-F\b.]
[T:trace]:[fname_list?A comma or whitspace separated list of function names, which should be traced during execution.]
[+?]
[c:compact?Dump the JSON objects read as compact as possible, i.e. no whitespaces.]
[d:debug?Enable JSONP debug output.]
\n\n\ajson_file\a
'
integer COMPACT=0 JSON_DEBUG=0
X="${ print ${Man.FUNC[MAIN]} ; }"
while getopts "${X}" option ; do
	case "${option}" in
		h) showUsage MAIN ; exit 0 ;;
		F) typeset +f ; exit 0 ;;
		H)	if [[ ${OPTARG%_t} != ${OPTARG} ]]; then
				${OPTARG} --man   # self-defined types
			else
				showUsage "${OPTARG}"   # function
			fi
			exit 0
			;;
		T)	if [[ ${OPTARG} == 'ALL' ]]; then
				typeset -ft ${ typeset +f ; }
				set -x
			else
				typeset -ft ${OPTARG//,/ }
			fi
			;;
		c) COMPACT=1 ;;
		d) JSON_DEBUG=1 ;;
		*) showUsage ;;
	esac
done
X=$((OPTIND-1))
shift $X
OPTIND=1

doMain "$@"

fi

#!/bin/ksh93

typeset -r VERSION='1.0' FPROG=${.sh.file} PROG=${FPROG##*/} SDIR=${FPROG%/*}
typeset -r X3URL='http://cert.int-x3.letsencrypt.org/' X3NAME='letsencryptX3'

function showUsage {
	[[ -n $1 ]] && X='-?' ||  X='--man'
	getopts -a ${PROG} "${ print ${USAGE} ; }" OPT $X
}

function getHostname {
	typeset HN=${ hostname; } X
	set -- ${ getent hosts ${HN} ; }
	shift
	for X ; do
		[[ $X =~ \..+\.[a-zA-Z]+ ]] || continue
		HOSTNAME="$1" && DOMAIN="${HOSTNAME#*.}" && break
	done
}

unset HOSTNAME DOMAIN LE_TMP DEFAULT
typeset HOSTNAME DOMAIN LE_TMP
getHostname
typeset -A DEFAULT=(
	[URL]="https://le.${DOMAIN}/certs"
	[DST]='/data/httpd/conf/ssl.crt'
	[REHASH]='./hashCerts'
	[SVCS]='apache24'
)

function cleanup {
    [[ -n ${LE_TMP} && -d ${LE_TMP} ]] || return 0
    rm -rf "${LE_TMP}"
}

function restartSvcs {
	typeset SVCADM='svcadm' START_CMD='enable -s' STOP_CMD='disable -st' X
	integer USE_OLD=0

	if [[ ${ uname -s ; } != 'SunOS' ]]; then
		SVCADM=${ whence + ; }		# one may replace '+' with 'sudo'
		START_CMD='start'  STOP_CMD='stop'
		X=${ whence systemctl ; }
		[[ -z $X ]] && USE_OLD=1 || SVCADM+=' systemctl'
	fi
	# or simply change this part as needed
	for X in ${OPTS[SVCS]} ; do
		(( VERB )) && print -u2 "Restarting service '$X' ..."
		if (( USE_OLD )); then
			${SVCADM} service "$X" stop
			sleep 3
			${SVCADM} service "$X" start
		else
			${SVCADM} ${STOP_CMD} "$X"
			${SVCADM} ${START_CMD} "$X"
		fi
	done
}

function fetchURL {
	typeset URL="$1" D="$2" F="${LE_TMP}/${D##*/}" H
	integer LE=0 RES=1

	[[ -n $3 ]] && LE=1
	(( VERB )) && print -u2 "Getting '${URL}' ..."
	H=${ curl --capath "${OPTS[DST]}" -RsSH Expect: -o "$F" -D - "${URL}"; }

	if (( $? )); then
		print -u2 "${URL} => failed to fetch" && return 1
	elif [[ ! -s $F ]]; then
		print -u2 "${URL} => empty response" && return 2
	fi

	H="${H#*$'\r'}"
	set -- ${.sh.match}
	if (( $2 != 200 )); then
		shift 2
		print -u2 "${URL} => " "$@"
		return 3
	fi

	if (( LE )); then
		H="${F%.crt}.der"
		mv "$F" "$H"
		openssl x509 -in "$H" -inform DER -outform PEM -out "$F" 2>/dev/null
		RES=$?
		touch -r "$H" "$F"
	else
		openssl x509 -in "$F" -outform DER -out "${F%.crt}.der" 2>/dev/null
		RES=$?
	fi
	if (( RES )); then
		print -u2 "${URL} => file not PEM encoded"
	elif [[ ! -e $D ]] || [[ $D -ot $F ]]; then
		(( VERB )) && print -u2 "Overwriting '$D' ..."
		cp -p "$F" "$D" && return 0
	elif (( VERB )); then
		print -u2 "No update for '$D'."
	fi
	return 4
}

function doMain {
	typeset X F D URL H
	integer UPDATE

	(( ! OPTS[LEX] )) && [[ -z $1 ]] && showUsage 1 && return 0

	for X in ${!DEFAULT[@]} ; do
		[[ -z ${OPTS["$X"]} ]] && OPTS["$X"]="${DEFAULT[$X]}"
	done
	LE_TMP=${ mktemp -dt acme.XXXXXX ; }
	[[ -z ${LE_TMP} ]] && return 1

	(( OPTS[LEX] )) && fetchURL "${X3URL}" "${OPTS[DST]}/${X3NAME}".crt 1

	for X in "$@" ; do
		[[ -z $X ]] && continue
		fetchURL "${OPTS[URL]}/$X".crt "${OPTS[DST]}/$X".crt
	done
	(( UPDATE )) && restartSvcs
}

USAGE="[-?${VERSION}"' ]
[-copyright?Copyright (c) 2019 Jens Elkner. All rights reserved.]
[-license?CDDL 1.0]
[+NAME?'"${PROG}"' - update LE certificates and restart related services.]
[+DESCRIPTION?Download the certificates \aURL\a\b/\b\adomain\a\b.crt\b and copy the file with the same name to the given certificate directory if it is newer than the existing file with the same name or the file does not yet exist. If copied, the rehash utility gets called to update hash-symlinks to the related certificates. Finally related services get restarted.]
[h:help?Print this help and exit.]
[F:functions?Print a list of all functions available.]
[T:trace]:[functionList?A comma separated list of functions of this script to trace (convinience for troubleshooting).] 
[+?]
[d:dir]:[path?The directory, where the new certificates should be stored. Default: '"${DEFAULT[DST]}"']
[r:rehash]:[path?The \apath\a to the utility, which should be called from within the certificate directory to update the hashed symlinks to related certificates. Default: '"${DEFAULT[REHASH]}"']
[s:svc]:[name?If a certificate update happend, restart the service with the given \aname\a. For this on Solaris \bsvcadm\b(1M) otherwise \bsystemctl\b(8) will be used. Can be used multiple times. Default: '"${DEFAULT[SVCS]}"']
[u:url]:[URL?The download \aURL\a, which points to the directory containing re-newed certificates. Default: '"${DEFAULT[URL]}"']
[v:verbose?Just show the annoying details.]
[x:x3cert?Try to download the current \b'"Let's Encrypt Authority X3"'\b certificate, convert it into PEM format and save it in the certificate directory as \b'"${X3NAME}"'.crt\b. An update does not trigger a rehash or service restart.]
[+EXAMPLES?]{
	[+?'"${PROG}"' \a'"${HOSTNAME}"'\a \b'"${X3NAME}"']
	[+?]
	[+?'"${PROG}"' -d \a/data/web/httpd/conf/ssl.crt\a \\]
	[+?-u http://\a'"le.${HOSTNAME#*.}"'/certs\a -s apache2 \\]
	[+?\a'"le.${HOSTNAME#*.}"'\a]
	[+?]
	[+?'"${PROG}"' -d /tmp -x]
}
\n\n\adomain\a ...
'
unset OPTS VERB; typeset -A OPTS ; integer VERB=0
X="${ print ${USAGE} ; }"
while getopts "${X}" OPT ; do
	case ${OPT} in
		h) showUsage ; exit 0 ;;
		T)	if [[ ${OPTARG} == 'ALL' ]]; then
				typeset -ft ${ typeset +f ; }
			else
				typeset -ft ${OPTARG//,/ }
			fi
			;;
		F) typeset +f && exit 0 ;;
		d) OPTS[DST]="${OPTARG}" ;;
		r) OPTS[REHASH]="${OPTARG}" ;;
		s) OPTS[SVCS]+=" ${OPTARG//,/ }" ;;
		u) OPTS[URL]="${OPTARG}" ;;
		v) VERB=1 ;;
		x) OPTS[LEX]=1 ;;
		*) showUsage 1 ; exit 1 ;;
	esac
done

X=$((OPTIND-1))
shift $X && OPTIND=1
unset X

trap cleanup EXIT
doMain "$@"

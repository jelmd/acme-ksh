#!/bin/ksh93

typeset -r VERSION='1.0' FPROG=${.sh.file} PROG=${FPROG##*/} SDIR=${FPROG%/*}

# Browsers and OS often do not have the signers of LE certs in its stores
typeset -r \
	LE_X3URL='http://cert.int-x3.letsencrypt.org/' \
	LE_X3NAME='Let_s_Encrypt_Authority_X3' \
	TI_X3URL='https://www.identrust.com/node/935' \
	TI_X3NAME='DST_Root_CA_X3'

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
	[[ -z $PATH ]] && PATH='/bin:/usr/bin:/sbin:/usr/sbin' || PATH+=':/usr/sbin'
	typeset SVCADM='svcadm' START_CMD='enable -s' STOP_CMD='disable -st' X
	integer USE_OLD=0

	for X in ${OPTS[SCRIPTS]} ; do
		$X
	done

	if [[ ${ uname -s ; } != 'SunOS' ]]; then
		SVCADM=${ whence + ; }		# one may replace '+' with 'sudo'
		START_CMD='start'  STOP_CMD='stop'
		X=${ whence systemctl ; }
		[[ -z $X ]] && USE_OLD=1 || SVCADM+=' systemctl'
	fi
	# or simply change this part as needed. Stop/Start is important, because
	# apache may crash when the cert gets changed ...
	for X in ${OPTS[SVCS]} ; do
		(( VERB )) && print -u2 "Restarting service '$X' ..."
		if (( USE_OLD )); then
			${SVCADM} /usr/sbin/service "$X" stop
			sleep 3
			${SVCADM} /usr/sbin/service "$X" start
		else
			${SVCADM} ${STOP_CMD} "$X"
			${SVCADM} ${START_CMD} "$X"
		fi
	done
}

function fetchURL {
	typeset URL="$1" D="$2" F="${LE_TMP}/${D##*/}" H X=
	integer LE=0 RES=1
	typeset -a ARGS=(
		'--capath' "${OPTS[DST]}"
		'--silent'
		'--show-error'
		'--remote-time'
		'--header' 'Expect:'
		'--output' "$F"
		'--dump-header' '-'
	)

	[[ -n $3 ]] && LE=1
	(( VERB )) && print -u2 "Getting '${URL}' ..."

	if [[ ${URL:0:5} == 'file:' ]]; then
		(( LE )) && print -u2 "URL '${URL}' not allowed for LE." && return 1
		F=${URL:5}
		F=/${F##/}
		if [[ ! -e $F ]]; then
			(( VERB )) && print -u2 "No update for '$D'.\n"
			return 4
		fi
		RES=0
	else
		# http:
		[[ -n ${OPTS[NOPROXY]} ]] && ARGS+=( '--noproxy' )
		[[ -n ${OPTS[INSECURE]} ]] && ARGS+=( '--insecure' )
		H=${ curl "${ARGS[@]}" -- "${URL}" 2>${LE_TMP}/err.out; }

		if (( $? )); then
			H=$(<${LE_TMP}/err.out)
			print -u2 "${URL} => error:\n$H\n" && return 1
		elif [[ ! -s $F ]]; then
			print -u2 "${URL} => empty response\n" && return 2
		fi

		H="${H#*$'\r'}"
		set -- ${.sh.match}
		if (( $2 != 200 )); then
			shift 2
			print -u2 "${URL} => $@\n"
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
	fi

	if (( RES )); then
		print -u2 "${URL} => file not PEM encoded\n"
	elif [[ ! -e $D ]] || [[ $D -ot $F ]]; then
		(( VERB )) && print -u2 "Overwriting '$D' ...\n"
		cp -p "$F" "$D" && return 0
	elif (( VERB )); then
		print -u2 "No update for '$D'.\n"
	fi
	return 4
}

function doRehash {
	print
	if [[ -z ${OPTS[REHASH]} ]]; then
		print -u2 'No rehash utility set - skipping rehash'
		return 0
	fi
	cd ${OPTS[DST]} || return 1
	${OPTS[REHASH]}
}

function getIntermediates {
	integer UPDATE=0 C E=0
	typeset DST X URL

	for DST in LE TI ; do
		print
		typeset -n URL=${DST}_X3URL NAME=${DST}_X3NAME
		[[ -n ${OPTS[NAME]} ]] && X="${OPTS[NAME]}" || X="${NAME}".crt
		[[ -z $X ]] && print -u2 "${DST}_X3NAME is not set" && continue
		fetchURL "${URL}" "${OPTS[DST]}/$X" 1
		C=$?
		(( C == 4 )) && continue
		if (( C == 0 )); then
			(( UPDATE++ ))
		else
			(( VERB )) && print -u2 '\nTrying local cert store ...'
			# try to fetch from local cert store
			fetchURL "${OPTS[URL]}/${NAME}".scrt "${OPTS[DST]}/$X"
			C=$?
			(( C == 4 )) && continue
			(( C )) && (( E++ )) || (( UPDATE++ ))
		fi
		if (( C == 0 )) && [[ ${DST} == 'TI' ]]; then
			cp "${OPTS[DST]}/$X" ${LE_TMP}/dst.p7b
			openssl pkcs7 -in ${LE_TMP}/dst.p7b -inform DER -print_certs \
				-out ${LE_TMP}/dst.crt && cp ${LE_TMP}/dst.crt "${OPTS[DST]}/$X"
		fi
	done
	(( E)) && print -u2 'Perhaps using option -i may help to workaround.'
	(( UPDATE )) && return 0 || return 1
}

function doMain {
	typeset X F D URL H
	integer UPDATE=0 C

	(( ! OPTS[LEX] )) && [[ -z $1 ]] && showUsage 1 && return 0

	for X in ${!DEFAULT[@]} ; do
		[[ -z ${OPTS["$X"]} ]] && OPTS["$X"]="${DEFAULT[$X]}"
	done
	LE_TMP=${ mktemp -dt acme.XXXXXX ; }
	[[ -z ${LE_TMP} ]] && return 1

	if [[ -n ${OPTS[NAME]} ]]; then
		if [[ ! ${OPTS[NAME]} =~ ^[a-zA-Z0-9._@][-+a-zA-Z0-9._@]*$ ]]; then
			print -u2 "Invalid characters in '${OPTS[NAME]}' - exiting."
			return 2
		fi
	fi
	(( OPTS[LEX] )) && getIntermediates && (( REHASH++ ))

	for X in "$@" ; do
		[[ -z $X ]] && continue
		[[ -n ${OPTS[NAME]} ]] && D="${OPTS[NAME]}" || D="$X".crt
		fetchURL "${OPTS[URL]}/$X".crt "${OPTS[DST]}/$D" && (( UPDATE++ ))
	done
	(( UPDATE | REHASH )) && doRehash
	(( UPDATE )) && restartSvcs
}

USAGE="[-?${VERSION}"' ]
[-copyright?Copyright (c) 2019 Jens Elkner. All rights reserved.]
[-license?CDDL 1.0]
[+NAME?'"${PROG}"' - update LE certificates and restart related services.]
[+DESCRIPTION?Download the certificate \aURL\a\b/\b\adomain\a\b.crt\b and copy the file with the same name to the given certificate directory if it is newer than the existing file with the same name or the file does not yet exist. If copied, the rehash utility gets called to update hash-symlinks to the related certificates. Finally related services get restarted.]
[h:help?Print this help and exit.]
[F:functions?Print a list of all functions available.]
[T:trace]:[functionList?A comma separated list of functions of this script to trace (convinience for troubleshooting).] 
[+?]
[d:dir]:[path?The directory, where the new certificates should be stored. Default: '"${DEFAULT[DST]}"']
[i:insecure?Do not verify SSL certificates presented by any server. For more information see \bcurl\b(1) flag \b--insecure\b.]
[n:name]:[fname?Store the received cert using the \afname\a as its basename instead of \adomain\a\b.crt\b . If more than one domain is given, all certs will be stored under the same name, yes!]
[P:no-proxy?Disable the use of any proxy. Per default a proxy is used, if configured - see \bcurl\b(1) for more information.]
[r:rehash]:[path?The \apath\a to the utility, which should be called from within the certificate directory to update the hashed symlinks to related certificates. Default: '"${DEFAULT[REHASH]}"']
[S:script]:[path?If a certificate update happend, run the script \apath\a before all related services get restarted. Can be used multiple times. Per default the list of scripts to run is empty.]
[s:svc]:[name?If a certificate update happend, restart the service with the given \aname\a. If \aname\a is an empty string, no service gets restarted. The executing user should have the related permissions for \bsvcadm\b(1M) on Solaris, for \bsystemctl\b(8) otherwise. Can be used multiple times. Default: '"${DEFAULT[SVCS]}"']
[u:url]:[URL?The download \aURL\a, which points to the directory containing re-newed certificates. If the URL starts with \bfile:\b, the remaining part gets used as the directory to look for new re-newed certificates. Default: '"${DEFAULT[URL]}"']
[v:verbose?Just show the annoying details.]
[x:x3cert?Try to download the certificates of intermediate and root CAs.  An update does not automatically trigger a service restart.]
[+EXAMPLES?]{
	[+?'"${PROG}"' \a'"${HOSTNAME}"'\a \b'"${LE_X3NAME}"']
	[+?]
	[+?'"${PROG}"' -d \a/data/web/httpd/conf/ssl.crt\a \\]
	[+? -u http://\a'"le.${HOSTNAME#*.}"'/certs\a -s apache2 \\]
	[+? -i \a'"le.${HOSTNAME#*.}"'\a]
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
		i) OPTS[INSECURE]=1 ;;
		n) OPTS[NAME]="${OPTARG}" ;;
		P) OPTS[NOPROXY]=1 ;;
		r) OPTS[REHASH]="${OPTARG}" ;;
		S) OPTS[SCRIPTS]+=" ${OPTARG//,/ }" ;;
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

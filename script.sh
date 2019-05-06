#!/bin/ksh93

typeset -r VERSION='1.0' LIC='[-?'"${VERSION}"' ]
[-copyright?Copyright (c) 2018 Jens Elkner. All rights reserved.]
[-license?CDDL 1.0]'

# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License") version 1.1!
# You may not use this file except in compliance with the License.
#
# See LICENSE.txt included in this distribution for the specific
# language governing permissions and limitations under the License.
#
# Copyright 2018 Jens Elkner (jel+acme-src@cs.ovgu.de)

# to get the annotation numbers right
ACME='https://tools.ietf.org/html/draft-ietf-acme-acme-07'
#https://github.com/letsencrypt/boulder/commits/master/docs/acme-divergences.md
DIVERGENCE_INFO='2018-10-10'

# start of boiler plate
SDIR=${.sh.file%/*}
typeset -r FPROG=${.sh.file}
typeset -r PROG=${FPROG##*/}

#include "includes/log.kshlib"
#include "includes/man.kshlib"

function showUsage {
	typeset WHAT="$1" X='--man'
	[[ -z ${WHAT} ]] && WHAT='MAIN' && X='-?'
	getopts -a "${PROG}" "${ print ${Man.FUNC[${WHAT}]}; }" OPT $X
}

alias json='typeset -uli'
alias json_t='typeset -usi'
#include "includes/json.sh"

unset DEFAULT ; typeset -Ar DEFAULT=(
	[CFG-DIR]="${HOME}/.acme"
	[PREFIX]='.well-known/acme-challenge'
	[RESPONSE_DIR]='/data/http/sites/my_site/htdocs/.well-known/acme-challenge'
	[ACCOUNT]='default'
	[KEY_TYP]='P-256'
	[KEY_TYP_DOM]='RSA256-2048'
	[CA_NAMES]='le:https://acme-v01.api.letsencrypt.org/directory test:https://acme-staging.api.letsencrypt.org/directory'
	[CA]='test'
	[PORT]=0
	[TIMEOUT]=60
	[MY_RESPONSE]=0
	[RSA_MIN_KEYSZ]=2048
	[DAYS]=30
	[FORCE_STATUS]=0
	[FORCE_AUTH]=0
	[REASON]=0
)

# filter, what can go into a config file
unset CFG_FILTER 
typeset CFG_FILTER="${!DEFAULT[@]}" ; CFG_FILTER="${CFG_FILTER//+(CFG-DIR|RSA_MIN_KEYSZ) }"
CFG_FILTER+=' PFEXEC UTIL UTIL_CFG SLANG NOT_BEFORE NOT_AFTER CERT_DIR'
typeset -r CFG_FILTER

Man.addFunc LE_ENV '' '[+NAME?\ble.conf\b configuration variables]
[+DESCRIPTION?If in the configuration directory used by this script a file named \ble.conf\b is found, is gets read to augment or overwrite the default configuration hardocded into this script. After this, and if the directory contains an \ba-\b\aaccount\a\b.conf\b config file, this one gets read and may augment or overwrite the configuration obtained so far. \aaccount\a is the alias of the account to use when talking to the CA servers. Finally, if the directory contains a \bc-\b\aca_name\a\b.conf\b, this file gets read and may augment or overwrite the configuration obtained so far (\aca_name\a is the alias of the CA to use).]
[+?The config file is a normal text file, which should have a \akey\a\b=\b\avalue\a pair on each line. Actually it is used as a ksh93 snippet and thus it can even be used as a startup hook, however, when doing so you risk that it will lead to unexpected results. At the end the global variables set in this config file count - they get exposed via \bset\b(1) and read in by this script. So make sure, you use proper quoting and avoid unsupported multi-line or not simple string values. NOTE that most of these parameters can be overwritten for a single run using appropriate CLI options.]
[+?For convinience you may run this script with appropriate options and \b-c config\b to dump the current config and use this as the start for your customizations.]
[+ENVIRONMENT VARIABLES?The environment variables honored in an \ble.conf\b file are:]{
	[PREFIX?The URL path prefix to use for HTTP based challenge responses without any leading slash. Default: \b'"${DEFAULT[PREFIX]}"'\b]
	[RESPONSE_DIR?The directory, where the file should be stored, which contains the answer for a previously received ACME challenge. It should be the path the http server uses to satisfy \b/${PREFIX}/*\b requests from ACME servers (or redirects from related domain http servers). Default: \b'"${DEFAULT[RESPONSE_DIR]}"'\b]
	[ACCOUNT?The alias of the account to use. It is just a local identifier, which allows less clutter/makes it easier to refer to an account on an ACME server. CLI option \b-a ...\b overwrites this setting. Default: \b'"${DEFAULT[ACCOUNT]}"'\b]
	[KEY_TYP?The type of key and SHA hash to use. For RSA keys it should have the prefix "RSA" followed by the number of bits of hash sum to use, followed by a dash (-) and the keysize in bits, e.g "RSA512-4096". LE requirement for RSA keys is a length of 2048..4096 bit. For elliptic curve (EC) based keys it should set the name of the curve to use. This script supports "RSA256-\aKSZ\a", "RSA384-\aKSZ\a", "RSA512-\aKSZ\a" with a \aKSZ\a >= 2048 bits, "P-256", "P-521" and "P-384", whereby the last one is not supported by LE. Default: \b'"${DEFAULT[KEY_TYP]}"'\b]
	[KEY_TYP_ACC?The type of key to use for account related operations. Default: \bKEY_TYP\b]
	[KEY_TYP_DOM?The type of key to use for domain related operations. Default: \bKEY_TYP\b]
	[CA_NAMES?A space separated list of known Certificate Authorities (CAs) supported by this script. Each entry has the format \aname\a\b:\b\aurl\a, whereby \aname\a denotes the short name or alias of the CA, and \aurl\a the coresponding URL to use to get an ACME directory response. Make sure, that no name collisions occure and \bCA\b - if set - uses an alias from this list. Note that \aname\a is just a local identifier, which allows less clutter/makes it easier to refer to a directory \aurl\a.]
	[CA?The name aka alias for the Certificate Authority (CA) to use. It has to be part of \bCA_NAMES\b. For production use \ble\b is recommended. CLI option \b-A ...\b overwrites this setting. Default: \b'"${DEFAULT[CA]}"'\b]
	[UTIL?The name of the external \atool\a to use to GET and POST contents via https. Per default it is automatically determined via \bPATH\b with preferring \bcurl\b(1) over \bwget\b(1). If \atool\a contains no slashes, \bPATH\b needs to be set correctly to find it. Otherwise if it is not absolute, it gets resolved via the current working directory as usual. In any way it must end with one of the three names mentioned before to be able to use correct options. CLI option \b-u ...\b overwrites this setting.]
	[UTIL_CFG?This script uses a http-util to exchange messages with ACME servers - usually curl or wget. If this option is used, \apath\a will be used as explicit configuration/rc file and thus one is able to adjust the behavior of \bUTIL\b as needed, e.g. wrt. proxy usage etc.. CLI option \b-U ...\b overwrites this setting.] 
	[SLANG?Ask the ACME server to generate text messages using the given language. The value is a 2-lettercode for the language followed by a "-" with the 2 letter code for a country variant, e.g. "de-DE" (see "locale -a" w/o the trailing .encoding - encoding stays UTF-8). Invalid values are silently ignored.]
	[EMAIL?The e-mail address to use, when a new account gets registered. If no e-mail address should be submitted (which is allowed at least by LE), use a dash (-) instead of an \aaddress\a. CLI option \b-e ...\b overwrites this setting.]
	[NEWKEY?The value should be a file, which contains the new private key, which should be used for all further ACME operations for the related account and server. Obviously this option takes only effect, when the command \bchkey\b gets executed, otherwise it gets silently ignored. CLI option \b-k ...\b overwrites this setting. If this option is not set when the \bchkey\b command gets executed, a new private key gets generated on-the-fly.]
	[DOMAINS?The value should contain a comma separated list of domain identifiers, to which the specified command gets applied. It gets ignored for all account related operations, since they are completely decoupled from authorization and certification. CLI option \b-d ...\b overwrites this setting.]
	[PFEXEC?The utility to execute, if a command gets executed, which requires higher privileges (e.g. when listening on a privileged port). On Linux one may use for example \bsudo(8)\b or on Solaris \bpfexec\b(8). There is no default set, and thus all commands executed by default with the privileges of the user or role running this script. NOTE that e.g. \bsudo\b may require an interactive session to ask for a password and thus may fail, when it gets run e.g. as a cron job.]
	[PORT?The number of the port, which should be used to listen for HTTP based authorization requests from ACME servers. Right now this requires python 2.x or 3.x with the six compatibility and the standard library installed. The default value \b0\b indicates, that the challenge response gets just copied to the \bRESPONSE_DIR\b and in turn served by a webserver like Apache httpd. ACME servers use always port 80 (i.e. http://\adomain\a:80/'"${DEFAULT[PREFIX]}"'), so unless one has setup redirects on \aDOMAIN\a to a non-privileged port [and machine]] (best practice) PORT=80 is required. If the PORT is set to a value < 1024 one needs to use PFEXEC option as well, which runs the server with net-private privileges, so that it is able to bind to the specified PORT.]
	[TIMEOUT?Max. number of seconds the script should wait for ACME servers to verify a challenge. Default: \b'"${DEFAULT[TIMEOUT]}"'\b]
	[MY_RESPONSE?Use 1 to let you start your own client/script/etc. in order to answer challenge response requests from ACME servers (PORT gets ignored in this case). Default: \b0\b]
	[RSA_KEYSZ?The number of bits a generated RSA key should have. Keys with a length < '"${DEFAULT[RSA_MIN_KEYSZ]}"' gets rejected. Default: '"${DEFAULT[RSA_KEYSZ]}"'.]
	[DAYS?If a certificate expires in less than these number of days, it qualifies for renewal. LE certificates are valid for a max. period of 90 days. So if you use a value > 90 here, one forces the renewal of the related certificate. To avoid any trouble, LE recommends to renew certificates 30 days before its validity period ends. Default: '"${DEFAULT[DAYS]}"']
	[NOT_BEFORE?When getting/renewing a certificate, ask to set the start of its validity period to the given date value. This is just a hint, i.e. the ACME server can ignore it or even reject the request, if it cannot or is not willingly to set it. The format of the date is similar to what netnews date or GNU date accepts. "YYYY-mm-dd HH:MM:SS" is its simplest/safe input format, but things like "next week", or "in 10 days", etc. are ok as well (do not forget the quotes). You should always check, whether it follows your intention by using the "\b'"${PROG} -c check-date '\b\adate\a\b'\b"'" command!]
	[NOT_AFTER?Same as NOT_BEFORE, but applies to the end of the validity period of a certificate.]
	[FORCE_STATUS?If set to a number != 0, the status of all operation related domains gets fetched from ACME servers, even if unexperired cached status records are available.]
	[FORCE_AUTH?Force re-authorization of all domains in question, no matter, what their authorization status is right now.]
	[CERT_DIR?The directory, where all obtained certificate files should be stored as as well in PEM format as \adomain\a\b.crt\b. Default is empty, i.e. do not copy.]
	[CERT_EXT?Use the given extension for certificates stored in \aCERT_DIR\a instead of \b.crt\b]
	[REASON?When revoking a certificate, one may indicate via the given \anum\aber, why the certificate revocation is requested. Allowed values are from 0..10, except 7 (for more details see https://tools.ietf.org/html/rfc5280#section-5.3.1). Default: \b0\b (i.e. unspecified).]
}
]
\n\n-H LE_ENV'

Man.addFunc mergeB2A '' '[+NAME?mergeB2A - merge two associative arrays]
[+DESCRIPTION?Iterates over the associative array \avnameB\a and applies its non-empty values to the corresponding fields of the associative \avnameA\a.]
\n\n\avnameA\a \avnameB\a
'
function mergeB2A {
	typeset -n A=$1 B=$2
	typeset X
	for X in ${!B[@]} ; do
		[[ -n ${B[$X]} ]] && A[$X]="${B[$X]}"
	done
	return 0
}

Man.addFunc yorn '' '[+NAME?yorn - ask a yes or no question.]
[+DESCRIPTION?Ask the question by using \aqword1\a...\aqwordN\a as the prompt and \adefault\a as the default value for the answer (e.g. if a user just presses <ENTER>). If \adefault\a is neither "y" nor "n", no default will be used.]
[+RETURN VALUES?]{
	[+0?The user entered a value equivalent to "yes".]
	[+1?The user entered a value equivalent to "no".]
}
\n\n\adefault\a \aqword\a ...
'
function yorn {
	typeset D="$1"
	typeset -l A=
	shift
	typeset PROMPT="$@"' ('
	if [[ D == [yY] ]]; then
		D=y
		PROMPT+='Y/n): '
	elif [[ $D == [nN] ]]; then
		D=n
		PROMPT+='y/N): '
	else
		D=
		PROMPT+='y/n): '
	fi
	if [[ -t 1 ]]; then
		while : ; do
			read A?"${PROMPT}"
			[[ -z $A ]] && A=$D
			[[ $A == 'y' || $A == 'n' ]] && break
		done
	else
		A=$D
	fi
	[[ $A == 'y' ]]
}

Man.addFunc checkEnv '' '[+NAME?checkEnv - manage LC_*, NLSPATH env vars]
[+DESCRIPTION?If \bLC_ALL\b is set, all \bLC_*\b gets set to its value. Finally \bLC_NUMERIC\b and \bLC_TIME\b are set to \bC\b, \bTZ\b to \bUTC\b and \bLC_ALL\b as well as \bNLSPATH\b get unset.]
'
function checkEnv {
	if [[ -n ${LC_ALL} ]] ; then
		export LC_MONETARY="${LC_ALL}" LC_MESSAGES="${LC_ALL}" \
			LC_COLLATE="${LC_ALL}" LC_CTYPE="${LC_ALL}"
	fi
	if [[ -n ${LC_MESSAGES} ]]; then
		X=${LC_MESSAGES%.*}
		[[ $X == [a-z][a-z][-_][A-Z][A-Z] ]] && OPTS[SLANG]=${X//_/-}
	fi
	export LC_NUMERIC=C LC_TIME=C TZ=UTC
	unset NLSPATH LC_ALL
	return 0
}

Man.addFunc readCfg '' '[+NAME?readCfg - read in a name=value config file]
[+DESCRIPTION?Executes the given \aconfig\a file as a ksh93 script in its own context and puts all variables produced this way into the given associative array \avnameA\a using the variable name as key and ${key} as its value. To restrict the keys accepted, one may provide a comma or space separated \akey_list\a of allowed var names as a 3rd argument. Unaccepted keys are silently ignored. Default variables set by the shell are always ignored. Ideally the config file is only a \akey\a=\avalue\a line-by-line list. A value which spans multiple lines or uses single or double quotes not as its first and last character may lead to unexpected results/values.]
[+ENVIRONMENT VARIABLES?\bHOME\b, \bLOGNAME\b, \bLC_CTYPE\b, \bLC_NUMERIC\b, \bLC_TIME\b, \bTZ\b]
[+SEE ALSO?\benv\b(1)]
\n\n\avnameA\a \aconfig\a [\akey_list\a]
'
function readCfg {
	[[ -z $1 || -z $2 ]] && Log.fatal "fn $0: arg0,1 missing - SW bug" && exit 1

	typeset -n V=$1 || exit 1
	[[ -f $2 ]] || return 0

	(( VERB )) && Log.info "Reading '$2' ..."
	typeset IN="$2" F=${LE_TMP}/cfg.sh MARKER='@#@@#@@#@@#@@#@@#@@#@@#@@#@@#@='
	typeset X
	typeset -Ai ALLOW
	integer SEEN=0 FILTER=0
	if [[ -n $3 ]]; then
		for X in ${3//,/ } ; do
			[[ -n $X ]] && ALLOW[$X]=1
		done
		FILTER=${#ALLOW[@]}
	fi

	# make it a little bit more robust and usewr friendly
	print "typeset HOME='${HOME}' LOGNAME='${LOGNAME}' LC_CTYPE='${LC_CTYPE}'" \
		"LC_NUMERIC='${LC_NUMERIC}' LC_TIME='${LC_TIME}' TZ='${TZ}'" \
		>$F || exit 2
	cat "${IN}" >>$F
	print 'print "'"${MARKER}"'"\nset' >>$F

	env -i /bin/ksh93 $F 2>/dev/null | while read LINE ; do
		if (( ! SEEN )); then
			[[ ${LINE} == ${MARKER} ]] && (( SEEN++ ))
			continue
		fi
		[[ ${LINE} == +([A-Z_])=* ]] || continue
		VAL="${LINE#*=}"
		KEY="${.sh.match%=}"
		[[ ${KEY} =~ ^(COLUMNS|ENV|FCEDIT|HISTCMD|IFS|JOBMAX|KSH_VERSION|LINENO|LINES|MAILCHECK|OPTIND|PPID|PS[1-4]|PWD|RANDOM|SECONDS|SHELL|SHLVL|TMOUT|LC_.*|HOME|LOGNAME|TZ|LE_TMP)$ ]] \
			&& continue
		[[ ${VAL:0:2} == "\$'" ]] && VAL=${ printf "${VAL:2:${#VAL}-3}" ; } #"
		[[ ${VAL:0:1} == "'" || ${VAL:0:1} == '"' ]] && VAL="${VAL:1:${#VAL}-2}"
		(( FILTER && ! ALLOW[${KEY}] )) && continue
		[[ ${VAL:0:2} == '( ' && ${VAL:-2:2} == ' )' ]] && \
			V[${KEY}]=( ${VAL:2:${#VAL}-4} ) || V[${KEY}]="${VAL}"
	done
	X="${CFG[SLANG]}"
	if [[ -n $X ]]; then
		[[ $X == {2}[a-z][-_]{2}[A-Z] ]] && CFG[SLANG]=${X//_/-} || CFG[SLANG]=
	fi
	return 0
}

Man.addFunc checkDir '' '[+NAME?checkDir - check dir availability]
[+DESCRIPTION?Checks, whether the given \bdir\b exists. If not, it tries to create it. As a side effect, on success the \bOLDPWD\b env var gets set to this directory (because of cd usage).]
\n\n\adir\a
'
function checkDir {
	[[ -z $1 ]] && Log.fatal "fn $0: arg0 missing - SW bug" && exit 1
	if [[ ! -e $1 ]]; then
		mkdir -p "$1" || return 1
	fi
	cd "$1" || return 2
	cd ~-
	return 0
}

Man.addFunc cleanup '' '[+NAME?cleanup - cleanup the workspace of the script.]
[+DESCRIPTION?Removes the temporary directory \bLE_TMP\b and all its contents unless instructed via keep option not to do so.]
'
function cleanup {
	[[ -n ${LE_TMP} && -d ${LE_TMP} ]] || return 0
	(( OPTS[KEEP] )) && \
		Log.warn "Remove ${LE_TMP} when not needed anymore!" && return 0
	rm -rf "${LE_TMP}"
}

Man.addFunc getConfig '' '[+NAME?getConfig - prepare the configuation to use]
[+DESCRIPTION?Applies the builtin config (see \bDEFAULT[]]\b) to the given associative array \avnameA\a, determines the config dir to use, and sets \avnameA\a\b[CFG-DIR]]\b to it. After this the following config files get read and merged to \avnameA\a, one after another in the given order: \ble.conf\b, \ba-\b\avnameA\a\b[ACCOUNT]].conf\b, \bc-\b\avnameA\a\b[CA]].conf\b. Options given on the  CLI have higest priority and thus gets always merged into \avnameA\a after a file has been read.]
[+?As a side effect this function also creates the temp directory to use for further work and sets the global var \bLE_TMP\b accordingly.]
\n\n\avnameA\a
'
function getConfig {
	typeset -n CFG=$1
	typeset X T
	mergeB2A CFG DEFAULT || return 1
	integer ERR=0 N

	if [[ -n ${OPTS[LANG]} ]]; then
		CFG[SLANG]=${OPTS[LANG]}
		OPTS[SLANG]=					# allow to override
	fi

	# handle default, config, and options in this order
	typeset CFG_DIR="${OPTS[CFG-DIR]}" T X URL CA
	[[ -z ${CFG_DIR} ]] && CFG_DIR="${CFG[CFG-DIR]}"
	checkDir "${CFG_DIR}" || return 2
	OPTS[CFG-DIR]="${CFG_DIR}"	# makes it easier to merge back

	# required by readCfg()
	LE_TMP=${ mktemp -dt acme.XXXXXX ; }		# global var
	if [[ -z ${LE_TMP} ]]; then
		Log.fatal 'Unable to create a temporary directory.'
		return 3
	fi

	readCfg CFG "${CFG_DIR}/le.conf" "${CFG_FILTER}" || return 4
	mergeB2A CFG OPTS || return 5				# CLI has higher priority

	readCfg CFG "${CFG_DIR}/${CFG[ACCOUNT]}.conf" "${CFG_FILTER}" || return 6
	mergeB2A CFG OPTS || return 7				# CLI has higher priority

	CA=${CFG[CA]}
	[[ -z ${CA} ]] && Log.fatal 'No CA configured.' && return 8

	readCfg CFG "${CFG_DIR}/${CFG[CA]}.conf" "${CFG_FILTER}" || return 9
	mergeB2A CFG OPTS || return 10				# CLI has higher priority

	[[ -z ${CFG[KEY_TYP_ACC]} ]] && CFG[KEY_TYP_ACC]=${CFG[KEY_TYP]}
	[[ -z ${CFG[KEY_TYP_DOM]} ]] && CFG[KEY_TYP_DOM]=${CFG[KEY_TYP]}

	CFG[ACCOUNT-URL-FILE]="${CFG_DIR}/a-${CFG[ACCOUNT]}.url"

	# fail early
	if (( CFG[PORT] < 0 || CFG[PORT] > 65534 )); then
		Log.fatal "Invalid port '${CFG[PORT]}'."
		(( ERR++ ))
	fi

	N=1
	for X in ${CFG[CA_NAMES]} ; do
		T=${X%%:*}
		URL=${.sh.match:1}
		[[ $T == ${CA} ]] && CFG[CA-URL]="${URL}" && N=0 && break
	done
	(( N )) && (( ERR++ )) && Log.fatal "CA named '${CA}' not found in CA_NAMES"
	if [[ -n ${CFG[PFEXEC]} ]]; then
		if ! whence -q ${CFG[PFEXEC]} ; then
			Log.fatal "PFEXEC utility '${CFG[PFEXEC]}' not executable."
			(( ERR++ ))
		fi
	fi
	# connect timeout
	(( CFG[TIMEOUT] < 0 )) || CFG[TIMEOUT]=60
	if [[ -n ${OPTS[DEBUG-FN]} ]]; then
		X= T=
		set -s ${OPTS[DEBUG-FN]}
		while [[ -n $1 ]]; do
			[[ $T == $1 ]] || X+=",$1"
			T="$1"
			shift
		done
		CFG[DEBUG-FN]="$X,"
	fi

	(( CFG[DAYS] < 0 )) && Log.warn "'DAYS' has a negative value. So only" \
		'already expired certificates qualify for renewal - probably not' \
		'what you want!'
	if [[ -n ${CFG[NOT_BEFORE]} ]]; then
		N=${ printf '%(%s)T' "${CFG[NOT_BEFORE]}" ; }
		if (( $? )); then
			Log.fatal "Invalid 'NOT_BEFORE' date (${CFG[NOT_BEFORE]})."
			(( ERR++ ))
		fi
	fi
	if [[ -n ${CFG[NOT_AFTER]} ]]; then
		N=${ printf '%(%s)T' "${CFG[NOT_AFTER]}" ; }
		if (( $? )); then
			Log.fatal "Invalid 'NOT_AFTER' date (${CFG[NOT_AFTER]})."
			(( ERR++ ))
		fi
	fi
	CFG[CERT_EXT]="${CFG[CERT_EXT]##.}"
	if [[ -n ${CFG[REASON]} ]]; then
		if [[ ! ${CFG[REASON]} =~ ^[0-9]+$ ]] ; then
			Log.fatal "The certificate revocation REASON '${CFG[REASON]}' is" \
				'not allowed. Use a number in the range of 0..10, except 7.'
			(( ERR++ ))
		elif (( CFG[REASON] < 0 || CFG[REASON] > 10 || CFG[REASON] == 7 )); then
			Log.fatal 'The certificate revocation REASON code is out of range.'\
				'Use a number in the range of 0..10, except 7.'
			(( ERR++ ))
		fi
	fi
	checkDir ${CFG[CFG-DIR]}/${CFG[CA]} || (( ERR++ ))
	return ${ERR}
}

Man.addFunc dumpArray '' '[+NAME?dumpArray - dump the content of an associative array]
[+DESCRIPTION?Dumps the \akey\a\b='"'\avalue\a'"' entries of the given associative array \avnameA\a line-by-line. If one or more \aakey\a are given, an explicit \aakey\a\b=\b gets emitted if \avnameA\a does not contain it.]
\n\n\avnameA\a [\aakey\a ...]
'
function dumpArray {
	typeset -n C=$1
	typeset -A MISC
	shift
	[[ -n $1 ]] && for X ; do MISC["$X"]=1 ; done
	for X in ${!C[@]} ; do
		print "${X}='${C[$X]}'"
		MISC["$X"]=
	done
	for X in ${!MISC[@]} ; do
		[[ -n ${MISC["$X"]} ]] && print "${X}="
	done
}

Man.addFunc checkBinaries '' '[+NAME?checkBinaries - check, whether required external tools are available.]
[+DESCRIPTION?Checks, whether the required external tools like openssl, curl, etc. are available and stores their path into the given associative array \avnameA\a with the keys \bOPENSSL\b and \bUTIL\b.]
\n\n\avnameA\a
'
function checkBinaries {
	typeset -n CFG=$1
	typeset TOOL="${CFG[UTIL]}"
	integer ERR=0

	(( VERB )) && Log.info 'Looking for external tools ...'
	# openssl
	if [[ -n ${OPENSSL} ]]; then
		if [[ ${OPENSSL:0:1} != '/' ]]; then
			[[ ${OPENSSL} =~ / ]] && OPENSSL="${PWD}/${OPENSSL}" || \
				OPENSSL=${ whence ${OPENSSL} ; }
		fi
		if [[ ! -x ${OPENSSL} ]]; then
			Log.fatal "openssl binary ${OPENSSL} is not executable. Unsetting" \
				'OPENSSL env var may resolve this problem.'
			(( ERR++ ))
		fi
	else
		OPENSSL=${ whence openssl ; }
		[[ -z ${OPENSSL} ]] && Log.fatal 'openssl is required but was not' \
			'found. You may install it or adjust your \bPATH\b env var to' \
			'solve this problem.' && (( ERR++ ))
	fi
	(( ERR == 0 )) && CFG[OPENSSL]="${OPENSSL}"
	if [[ ${ uname -s ; } ]]; then
		X=${ whence -p gsed ; }
		[[ -z $X ]] && Log.fatal 'gsed (GNU sed) is required but was not' \
			'found. You may install it or adjust your \bPATH\b env var to' \
			'solve this problem.' && (( ERR++ ))
		CFG[SED]="$X"
	else
		CFG[SED]='sed'
	fi

	# curl or wget
	if [[ -n ${TOOL} ]]; then
		if [[ ${TOOL:0:1} != '/' ]]; then
			[[ ${TOOL} =~ / ]] && TOOL="${PWD}/${TOOL}" || \
				TOOL=${ whence ${TOOL} ; }
		fi
		if [[ ! -x ${TOOL} ]]; then
			Log.fatal "The http utility '${TOOL}' is not executable."
			(( ERR++ ))
		fi
		if [[ ! ${TOOL} =~ /(curl|wget)$ ]]; then
			Log.fatal "The http utility '${TOOL}' does neither end with" \
				'curl nor wget.'
			(( ERR++ ))
		fi
	else
		for X in curl wget ; do
			TOOL=${ whence curl; }
			[[ -n ${TOOL} ]] && break
		done
	fi
	if [[ -n ${TOOL} ]]; then
		CFG[UTIL]="${TOOL}"
		CFG[UTIL-SHORT]="${TOOL##*/}"
		CFG[AGENT]="acme-ksh/${VERSION} (ksh93/${.sh.version##* }"	# 6.1 §3
		X=${ ${TOOL} --version ; }
		X=${X##+([^0-9])}
		CFG[AGENT]+="; ${TOOL##*/}/${X%% *}"
		CFG[AGENT]+="; ${ uname -s; } ${ uname -r; } ${ uname -p; }"
		X=${ whence lsb_release ; }
		[[ -n $X ]] && CFG[AGENT]+="; ${ lsb_release -ds; }"
		CFG[AGENT]+=')'
	else
		Log.fatal 'No of the http-utils curl or wget found. You may' \
			'install one of them or adjust your \bPATH\b env var to solve' \
			'this problem.'
		(( ERR++ ))
	fi
	return ${ERR}
}

Man.addFunc fetch '' '[+NAME?fetch - fetch a certain URL]
[+DESCRIPTION?Fetches a HTTP[S]] ressource using the configured \bUTIL\b and \bUTIL-SHORT\b values from the given associative array \avnameCFG\a. However, if a dump directory is set (e.g. via option \b-D \b\a...\a) and saving is \bnot enabled\b via option \b-s\b, the previously dumped response header and body for the request are used, i.e. no fetching via HTTP of the given resource happens.]
[+?\avnamePARAM\a is an associative array containing the parameters for the request:]{
	[+URL?The URL to fetch. Mandatory!]
	[+METHOD?If empty, a normal GET will be used, otherwise the given method.]
	[+FOLLOW?If not empty, Location: headers are honored, i.e. follow redirects.]
	[+DATA?If \bMETHOD\b == \bPOST\b, the data to post.]
	[+DUMP?The basename of the dump file to use, if result dumping has been enabled. Default: Basename of the \bURL\b]
}
[+?On success (i.e. response from server obtained) the \bSTATUS_CODE\b and \bSTATUS_TXT\b for the response gets stored in the associative array \anameRES\a and the \bFILE\b entry will contain the name of the temporary file with the body of the server response, which gets overwritten on the next request. Furthermore the headers of the response get stored in \avnameRES\a as well (header names == keys, header values == values). Finally, if the server response contains a \bReplay-Nonce\b header, its value gets stored into \avnameCFG\a[NONCE]]\b.]
\n\n\avnameCFG\a \avnameRES\a \avnamePARAM\a
'
function fetch {
	typeset -n CFG=$1 RESULT=$2 PARAM=$3
	typeset URL="${PARAM[URL]}" X=${CFG[UTIL-SHORT]} T=${CFG[UTIL]} \
		CT KEY VAL DUMP= SLANG=
	typeset -a ARG
	RESULT[FILE]=${LE_TMP}/wget.out # wget mixes up stdout and stderr ...
	integer RES=0

	KEY="${CFG[UTIL_CFG]}"
	(( VERB )) && Log.info "Fetching '${URL}' ..."
	rm -f "${RESULT[FILE]}"
	if [[ -n ${CFG[TEST-DIR]} ]]; then
		DUMP="${CFG[TEST-DIR]}/"
		[[ -n ${PARAM[DUMP]} ]] && DUMP+="${PARAM[DUMP]}" || DUMP+="${URL##*/}"
		(( VERB )) && Log.info "Dump basename: ${DUMP}"
	fi
	if [[ -z ${CFG[ACCEPT-LANG]} ]]; then
		if [[ ${CFG[SLANG]} == {2}[a-z]-{2}[A-Z] ]]; then
			CFG[ACCEPT-LANG]="${CFG[SLANG]}, ${CFG[SLANG]:0:2};q=0.8, en;q=0.7"
		else
			CFG[ACCEPT-LANG]='en;q=0.7'
		fi
	fi
	if (( ! CFG[HTTP-DUMP] )) && \
		[[ -n ${DUMP} && -f ${DUMP}.body && ${DUMP}.header ]]
	then
		CT=$(<${DUMP}.header)
		cp ${DUMP}.body ${RESULT[FILE]}
	elif [[ $X == 'curl' ]]; then
		ARG=( '-s' '-A' "${CFG[AGENT]}" '--raw' '-D' '-' '-H' 'Expect:'
			'-H' "Accept-Language: ${CFG[ACCEPT-LANG]}" '-o' "${RESULT[FILE]}"
		)
		[[ -n ${KEY} ]] && ARG+=( '-K' "${KEY}" )
		if [[ ${PARAM[METHOD]} == 'HEAD' ]]; then
			ARG+=( '-I' )
		elif [[ ${PARAM[METHOD]} == 'POST' ]]; then
			ARG+=( -X 'POST' )
			X=${LE_TMP}/post.data
			print -rn -- "${PARAM[DATA]}" >$X
			[[ -s $X ]] && ARG+=( '--data-binary' "@$X"
				'-H' 'Content-Type: application/jose+json' )
		fi
		[[ -n ${PARAM[FOLLOW]} ]] && \
			ARG+=( '-L' ) || ARG+=( '--max-redirs' '0' )
		CT=${ $T "${ARG[@]}" "${URL}" ; }
		RES=$?
	elif [[ $X == 'wget' ]]; then
		ARG=( '-S' '-q' '-U' "${CFG[AGENT]}" '--content-on-error' '--no-hsts'
			"--header=Accept-Language: ${CFG[ACCEPT-LANG]}"
			'-O' "${RESULT[FILE]}"
		)
		[[ -n ${KEY} ]] && ARG+=( "--config=${KEY}" )
		if [[ ${PARAM[METHOD]} == 'HEAD' ]]; then
			ARG+=( '--method=HEAD' )
		elif [[ ${PARAM[METHOD]} == 'POST' ]]; then
			ARG+=( '--method=POST' )
			X=${LE_TMP}/post.data
			print -rn -- "${PARAM[DATA]}" >$X
			[[ -s $X ]] && ARG+=( "--body-file=$X"
				'--header=Content-Type: application/jose+json' )
		fi
		[[ -n ${PARAM[FOLLOW]} ]] || ARG+=( '--max-redirect=0' )
		CT=${ $T "${ARG[@]}" "${URL}" 2>&1; }	# wget emits headers to stderr
		RES=$?
		(( RES == 8 )) && RES=0
	else
		Log.fatal "Unknown http-util '$X'" && return 1
	fi
	if (( CFG[HTTP-DUMP] ))  && [[ -n ${DUMP} ]] ; then
		print "${URL}" >${DUMP}.url || { print $PWD; ls -l ; }
		print -n -- "${CT}" >${DUMP}.header || { print $PWD; ls -l ; }
		cp ${RESULT[FILE]} ${DUMP}.body || { print $PWD; ls -l ; }
		X="${LE_TMP}/post.data"
		if [[ -e $X ]] ; then
			cp $X ${DUMP}.post && rm -f $X || { print $PWD; ls -l ; }
		fi
	fi

	if (( RES )); then
		Log.warn "Failed to get '${URL}' - ${CFG[UTIL-SHORT]} exit code was" \
			"${RES}."
		return 1
	fi
	CT="${CT#*$'\n'}"
	set -- ${.sh.match}
	RESULT[STATUS_CODE]="$2"
	shift 2
	RESULT[STATUS_TXT]="$@"
	print -- "${CT}" | while read  KEY VAL ; do
		[[ -z ${KEY} ]] && continue
		RESULT["${KEY%:}"]="${VAL%$'\r'}"
	done
	RESULT[BODY]=$(<${RESULT[FILE]})
	if [[ -n ${RESULT[Replay-Nonce]} ]]; then
		CFG[NONCE]="${RESULT[Replay-Nonce]}"
		(( VERB )) && Log.info "New nonce '${CFG[NONCE]}'"
	fi
	return 0
}

# Boulder Section Section 7.1, 7.1.3, 7.2, 7.3.6, 7.4
typeset -A DIR07KEYS=( [nonce]='new-nonce' [account]='new-account'
	[impl]=7
	[order]='new-order' [authz]='new-authz' [revoke]='revoke-cert'
	[chkey]='key-change' [tos]='terms-of-service' [website]='website'
	[caids]='caa-identities'
	[existing]='only-return-existing' [extbind]='external-account-binding'
)
typeset -A DIR09KEYS=( [nonce]='newNonce' [account]='newAccount'
	[impl]=9
	[order]='newOrder' [authz]='newAuthz' [revoke]='revokeCert'
	[chkey]='keyChange' [tos]='termsOfService' [website]='website'
	[caids]='caaIdentities' [extacc]='externalAccountRequired'
	[existing]='onlyReturnExisting' [extbind]='externalAccountBinding'
)

# 7.1.1
Man.addFunc getDirectory '' '[+NAME?getDirectory - fetch the ACME Directory object (ACME 7.1.1)]
[+DESCRIPTION?Pulls the \bDirectory object\b given via \avnameCFG\a\b[CA-URL]]\b if not already done and augments \avnameCFG\a with the obtained URLs using \bURL-\b{nonce|account|order|authz|revoke|chkey|tos} as related keys. Furthermore \avnameCFG\a\b[IS_LE]]\b gets set to \b1\b if boulder server implementation (i.e. has LE divergences from ACME) gets detected, otherwise it gets set to \b0\b. Last but not least, if the response contains a "terms of service" URL it is checked, whether the user already agreed with it. If not, the user gets asked for it. If the user agrees, the file \bc-\aCA\a\b-TOS-\b\aURL_basename\a gets created containing the full URL and \avnameCFG\a\b[TOS]]\b gets set to it as well. If this file already exists, it is assumed, that it got created by this function and thus deduced, that the user already agreed with the CA'"'"'s TOS.]
[+?Another side effect is, that \avnameCFG\a\b[DIR-KEY]]\b gets set to the name of the associative array containing the mapping of certain implementation specific keys to more generic terms used in this script.]
[+?Note that if \avnameCFG\a\b[DIR-KEY]]\b is already set and \aforce\a is not given/empty, this function is a no-op.]
\n\n\avnameCFG\a [\aforce\a]
'
function getDirectory {
	typeset -n CFG=$1
	[[ -n ${CFG[DIR-KEY]} && -z $2 ]] && return 0

	typeset -A RES PROPS PARAMS=( [DUMP]='directory' [FOLLOW]=1 )
	typeset T= X= L N URL="${CFG[CA-URL]}"
	integer ID

	[[ -z ${URL} ]] && Log.fatal 'CA URL to use is not set.' && return 1
	(( VERB )) && Log.info 'Getting remote directory ...'

	PARAMS[URL]="${URL}"
	
	fetch CFG RES PARAMS || return 2
	if (( RES[STATUS_CODE] != 200 )); then
		T="Unexpected server response for '${URL}':\n"
		T+=$(<${RES[FILE]})
		Log.warn "$T"
		return 3
	fi
	if ! JSONP.readValue ID T <${RES[FILE]} ; then
		T=$(<${RES[FILE]})
		Log.warn "Invalid response from server for '${URL}':\n$T"
		return 4
	fi
	JSON.getVal ${ID} PROPS
	if [[ -n ${PROPS[newAuthz]} ]]; then
		CFG[DIR-KEY]=DIR09KEYS
	else
		CFG[DIR-KEY]=DIR07KEYS
	fi
	typeset -n DIRKEY=${CFG[DIR-KEY]}
	if [[ -z ${PROPS[${DIRKEY[account]}]} ]]; then
		# Boulder Section 7.1
		CFG[IS_LE]=1
		DIRKEY['account']='new-reg'
		DIRKEY['order']='new-cert'
	else
		CFG[IS_LE]=0
	fi
	typeset -A REV
	for T in ${!DIRKEY[@]} ; do
		REV[${DIRKEY[$T]}]="$T"
	done
	for T in ${!PROPS[@]} ; do
		N=${REV[$T]}
		X=
		if [[ -n $N ]] ; then
			JSON.getVal ${PROPS[$T]} X
			CFG["URL-$N"]="$X"
		elif [[ $T == 'meta' ]]; then
			typeset -A M
			JSON.getVal ${PROPS[$T]} M
			JSON.getVal ${M[${DIRKEY[tos]}]} X
			[[ -n $X ]] && CFG[URL-tos]="$X"
		fi
	done
	if [[ -n ${CFG[URL-tos]} ]]; then
		T="${CFG[URL-tos]}"
		X="${CFG[CFG-DIR]}/c-${CFG[CA]}-TOS_${T##*/}"
		if [[ ! -e $X ]]; then
			Log.warn '\n\tHave you read the "Terms of Service" document' \
				"provided\n\tvia '$T' ?\n"
			yorn ny 'I have read the "Terms of Service" document and agree'
			if (( $? )); then
				Log.fatal 'Without an agreement usage is not allowed.'
				return  4
			fi
			print -- "$T" >"$X"
		fi
		CFG[TOS]="$X"
	fi
	return 0
}

# 7.2
Man.addFunc getNonce '' '[+NAME?getNonce - get an ACME nonce (7.2).]
[+DESCRIPTION?Get an ACME server nonce to be able to send new post requests. Automatically calls \bgetDirectory\b(). On success \avnameCFG\a\b[NONCE]]\b gets set to the new nonce obtained. If this field is already set, this functions is a no-op unless \aforce\a is given and contains a non-empty value.]
\n\n\avnameCFG\a [\aforce\a]
'
function getNonce {
	typeset -n CFG=$1
	typeset -A RES PARAMS=( [METHOD]='HEAD' [DUMP]='nonce' )
	typeset X="${CFG[NONCE]}"

	[[ -n $X && -z $2 ]] && return 0

	getDirectory CFG || return 1
	[[ -n ${CFG[NONCE]} && ${CFG[NONCE]} != $X ]] && return 0

	(( VERB )) && Log.info 'Getting new nonce ...'
	if [[ ${CFG[URL-new-nonce]} ]]; then
		PARAMS[URL]="${CFG[URL-nonce]}"
	else
		# Boulder Section 7.1 - does not support new-nonce
		PARAMS[URL]="${CFG[CA-URL]}"
	fi
	fetch CFG RES PARAMS || return 2
	(( RES[STATUS_CODE] != 204 && RES[STATUS_CODE] != 200 )) && \
		Log.warn 'Unexpected Nonce response:' \
			"${RES[STATUS_CODE]} (${RES[STATUS_TXT]})"
	if [[ -z ${RES[Replay-Nonce]} ]]; then
		Log.warn 'No new nonce.'
		return 3
	fi
	# fetch puts it already into CFG[NONCE]
	return 0
}

# RFC 7515 Appendix C.
Man.addFunc str2base64url '' '[+NAME?str2base64url - base64url encode a string]
[+DESCRIPTION?Encodes the value of \avname\a as described in RFC 4648 "Base 64 Encoding with URL ..." + RFC 7515 "Terminology" and stores on success the encoded string back to \avname\a. If \aunescape\a is given and not empty, escape sequences contained in the string get converted to the corresponding character (printf ...) before its gets converted to base64url (e.g. \n to a byte with a value of 10, \xNN to a byte with a value of NN, etc.). Otherwise the string is taken as is (print -rn ...).]
\n\n\avnameCFG\a \avname\a [\aunescape\a]
'
function str2base64url {
	typeset -n CFG=$1 S=$2
	[[ -z $S ]] && return 0
	typeset X
	[[ -n $3 ]] && X=${ printf -- "$S" | ${CFG[OPENSSL]} base64  ; } || \
		X=${ print -rn -- "$S" | ${CFG[OPENSSL]} base64  ; }
	# the 62nd and 63rd char in the alphabet are '-','_' instead of '+','/'
	X=${X//+/-}
	X=${X//\//_}
	# and trailing pad chars must be stripped
	X=${X%%*(=)}
	# and without any line breaks (openssl does not create WS or other chars)
	X=${X//$'\n'}
	S=$X
}

Man.addFunc file2base64url '' '[+NAME?file2base64url - base64url encode a file]
[+DESCRIPTION?Encodes the content of \afile\a as described in RFC 4648 "Base 64 Encoding with URL ..." + RFC 7515 "Terminology" and stores on success the encoded string back to \avname\a.]
\n\n\avnameCFG\a \avname\a \afile\a
'
function file2base64url {
	typeset -n CFG=$1 S=$2
	typeset F="$3"

	[[ -z $F || ! -r $F ]] && Log.fatal "file '$F' is not readable." && \
		return 1
	S=
	if [[ -s $F ]]; then
		X=${ ${CFG[OPENSSL]} base64 -in "$F"; }
		[[ -z $X ]] && return 2
		# code dup from above
		X=${X//+/-}
		X=${X//\//_}
		X=${X%%*(=)}
		X=${X//$'\n'}
		S=$X
	fi
	return 0
}

Man.addFunc base64url2str '' '[+NAME?base64url2str - base64url decode a string.]
[+DESCRIPTION?Decodes the base64url encoded value of \avname\a as described in RFC 7515 and stores on success the encoded string back to \avname\a.]
\n\n\avnameCFG\a \avname\a
'
function base64url2str {
	typeset -n CFG=$1 B=$2
	[[ -z $B ]] && return 0
	typeset X=${B//-/+}
	X=${X//_/\/}
	integer M=${#X}
	(( M %= 4 ))
	if (( M == 0 )); then
		:		# no pad chars
	elif (( M == 2 )); then
		X+='=='	# two pad chars
	elif (( M == 3 )); then
		X+='='	# one pad char
	else
		return 1	# Illegal base64url string
	fi
	if [[ -n $3 ]]; then
		print -n -- "$X" | "${CFG[OPENSSL]}" base64 -d -A -out "$3"
		return $?
	fi
	T=${ print -n -- "$X" | ${CFG[OPENSSL]} base64 -d -A ; }
	[[ $T == $X ]] && return 1	# same as before means error
	B="$T"
}

KEY_WARNING='# WARNING:
# Make sure this file can only be read by you and your ACME operators.
# Everyone who has access to this key may manage your account and certificates
# on the related ACME servers!
'

Man.addFunc createPrivateKey '' '[+NAME?createPrivateKey - create a new private key.]
[+DESCRIPTION?Create a new key pair using the given \akey_type\a and store the generated private key (which also contains the public one) in the given \afile\a. The \akey_type\a is expected to have the same format as described in LE_ENV:\bKEY_TYP\b. On success \afile\a gets overwritten w/o notice and chmoded to 0600.]
\n\n\avnameCFG\a \afile\a \akey_type\a
'
function createPrivateKey {
	typeset -n CFG=$1
	typeset FILE="$2" X="$3" ARGS= TYP  X
	integer LEN

	[[ -z $X ]] && X='P-256'
	if [[ ${X:0:2} == 'P-' ]]; then
		TYP='EC'
		LEN="${X:2}"
		if (( LEN != 256 && LEN != 384 && LEN != 521 )); then
			Log.fatal "Unsupported EC curve '$X' -" \
				"use 'P-256', 'P-512' or 'P-384'."
			return 2
		fi
		ARGS="-algorithm EC -pkeyopt ec_paramgen_curve:$X" \
		ARGS+=' -pkeyopt ec_param_enc:named_curve'
	elif [[ $X == RSA@(256|384|512)-+([0-9]) ]]; then
		TYP='RSA'
		LEN="${X:7}"
		if (( LEN < 2048 )); then
			Log.fatal 'RSA key size < 2048 is unsupported.'
			return 3
		elif (( LEN > 4096 )); then
			Log.warn 'RSA key size > 4096 is not supported by LE servers.'
		fi
		(( LEN % 8 == 0 )) || Log.warn "RSA key size '$X' is not a" \
			'multiple of 8 - might cause problems.'
		ARGS+="-algorithm RSA -pkeyopt rsa_keygen_bits:${LEN}" \
		ARGS+=' -pkeyopt rsa_keygen_pubexp:65537'
	else
		Log.fatal "Unsupported private key type '$X'."
		return 4
	fi

	Log.info "Generating private key ($X) ..."
	(( VERB )) && Log.info "${CFG[OPENSSL]} genpkey ${ARGS}"
	${CFG[OPENSSL]} genpkey ${ARGS} -out ${LE_TMP}/akey || return 5
	print -n "${KEY_WARNING}" >"${FILE}" || return 6
	cat ${LE_TMP}/akey >>"${FILE}" || return 7
	print > ${LE_TMP}/akey
	chmod 0600 "${FILE}"
	(( VERB )) && Log.info "done (${FILE})." || Log.info 'done.'
}

Man.addFunc getKeyFilename '' '[+NAME?getKeyFilename - get the path of a private key.]
[+DESCRIPTION?Get the path of the file containing the private key for \avnameCFG\a\b[ACCOUNT]]\b or, if \ause_domain\a is given and not empty, for domain \avnameCFG\a\b[DOMAIN_ASCII]]\b. The result gets stored into \avnameRES\a.]
\n\n\avnameCFG\a \avnameRES\a [\ause_domain\a]
'
function getKeyFilename {
	typeset -n CFG=$1 NAME=$2
	if [[ -n $3 ]]; then
		if [[ -z ${CFG[DOMAIN_ASCII]} ]]; then
			Log.fatal 'Internal error: CFG[DOMAIN_ASCII] is not set.'
			return 1
		fi
		NAME="${CFG[CFG-DIR]}/${CFG[CA]}/r-${CFG[DOMAIN_ASCII]}.key"
	else
		if [[ -z ${CFG[ACCOUNT]} ]]; then
			Log.fatal 'Internal error: CFG[ACCOUNT] is not set.'
			return 1
		fi
		NAME="${CFG[CFG-DIR]}/a-${CFG[ACCOUNT]}.key"
	fi
	return 0
}

Man.addFunc getPrivateKey '' '[+NAME?getPrivateKey - get the private key for an account or domain.]
[+DESCRIPTION?Read in the private key for the account currently in use (\avnameCFG\a[ACCOUNT]]) or domain \avnameCFG\a[DOMAIN_ASCII]] if \aSUFFIX\a is given and is not empty. If no such key exists, a key gets created according to the type set via \avnameCFG\a fields \bKEY_TYP_ACC\b if \aSUFFIX\a is not given or empty, \bKEY_TYP_DOM\b otherwise (both fallback to \bKEY_TYP\b if unset). It gets stored in the config directory in use as well as into \avnameCFG\a[KEY\aSUFFIX\a]] (the PEM representation), \avnameCFG\a[KEY-DESC\aSUFFIX\a]] (the human readable textual representation). On success \avnameCFG\a[KEY-FILE\aSUFFIX\a] gets also set to the path of the PEM file containing the key.]
[+?If \avnameCFG\a[KEY\aSUFFIX\a]] is already set, this function is a no-op.]
[+SEE ALSO?\bLE_ENV\b]
\n\n\avnameCFG\a [\aSUFFIX\a]
'
function getPrivateKey {
	typeset -n CFG=$1
	typeset KEY SFX="$2" FILE
	[[ -n ${CFG[KEY${SFX}]} ]] && return 0

	getKeyFilename CFG FILE ${SFX} || return 1

	if [[ -e ${FILE} ]]; then
		KEY=${ ${CFG[OPENSSL]} pkey -noout -text -in ${FILE} ; }
		if [[ -z ${KEY} || ${KEY:0:12} != 'Private-Key:' ]]; then
			Log.fatal "Unable to read the private key from '${FILE}'." 
			return 2
		fi
		(( VERB )) && Log.info "Using private key '${FILE}'."
	else
		[[ -z ${SFX} ]] && KEY='ACC' || KEY='DOM'
		createPrivateKey CFG "${FILE}" "${CFG[KEY_TYP_${KEY}]}" || return 3
		KEY=${ ${CFG[OPENSSL]} pkey -noout -text -in ${FILE} ; }
	fi
	CFG[KEY-DESC${SFX}]="${KEY}"
	CFG[KEY${SFX}]=${ ${CFG[OPENSSL]} pkey -in "${FILE}" ; }	# avoid bloat
	CFG[KEY-FILE${SFX}]="${FILE}"
}

Man.addFunc getPublicKey '' '[+NAME?getPublicKey - get the public key for an account or domain.]
[+DESCRIPTION?Uses \bgetPrivateKey()\b to get the private key for the account currently in use (\avnameCFG\a[ACCOUNT]]) if \aSUFFIX\a was not specified or is empty, or for domain \avnameCFG\a\b[DOMAIN_ASCII]]\b. From this key the public portion gets extracted and stored into \avnameCFG\a[KEY-PUB\aSUFFIX\a]].]
[+?If \avnameCFG\a[KEY-PUB\aSUFFIX\a]] is already set, this function is a no-op.]
\n\n\avnameCFG\a [\aSUFFIX\a]
'
function getPublicKey {
	typeset -n CFG=$1
	typeset SFX="$2"
	[[ -n ${CFG[KEY-PUB${SFX}]} ]] && return 0

	getPrivateKey CFG "${SFX}" || return $?
	(( VERB )) && Log.info 'Extracting public key ...'
	KEY=${ print "${CFG[KEY${SFX}]}" | ${CFG[OPENSSL]} pkey -pubout ; }
	[[ -z ${KEY} ]] && return 11
	CFG[KEY-PUB${SFX}]="${KEY}"
	(( VERB )) && Log.info 'done.'
	return 0
}

Man.addFunc hexdump2str '' '[+NAME?hexdump2str - convert a hexdump to an escape sequence.]
[+DESCRIPTION?Converts the content given by \avname\a to an appropriate escaped string, which can be finally converted to its binary representation using the internal \bprint\b or \bprintf\b without option \b-r\b. The content of \avname\a is expected to contain hex bytes (0..2 [0-9a-fA-F]]) separated by a colon (\b:\b), only - e.g. ab:09:cd. Otherwise \avname\a stays as is.]
\n\n\avname\a
'
function hexdump2str {
	typeset -n S=$1
	typeset B= X
	for X in ${S//:/ } ; do
		[[ $X == {1,2}[0-9a-fA-F] ]] && return 1
		B+="\x$X"
	done
	S="$B"
}

Man.addFunc prepareJWS_PH '' '[+NAME?prepareJWS_PH - prepare JWS protected headers.]
[+DESCRIPTION?Prepares the two protected headers for JWS objects: one containing the \bjwk\b property and the other, which contains the \bkid\b property instead. They can be accessed via \bJSON\b and their JSON component IDs: \avnameCFG\a\b[JWS-PH-JWK]]\b and \avnameCFG\a\b[JWS-PH-KID]]\b. For convenience/direct access the JSON component IDs of the related fields gets stored into \avnameCFG\a as \bPH-ALG\b, \bPH-JWK\b, \bPH-NONCE\b, \bPH-URL\b as well. The 2 last ones need to be updated for each request and signature calculation should correspond to the 1st one.]
[+?The \bPH-JWK\b related object will contain only the required properties and thus can be used as is for JWK thumbprint generation (see RFC 7638).]
[+?It is required, that \avnameCFG\a\b[KEY-DESC]]\b contains the text form (openssl output) at least of the public key associated with the private key in use.]
[+?If \avnameCFG\a\b[JWS-PH-JWK]]\b and \avnameCFG\a\b[JWS-PH-KID]]\b are already set and not empty, this function is a no-op.]
[+?If \aSUFFIX\a is not empty, all mentioned key names of \avnameCFG\a get suffixed with \aSUFFIX\a. If in addition \aSUFFIX\a == "\b-NEW\b", \bKID\b header generation gets skipped and the JWK header will not contain a \bnonce\b property (as described for key-roll-over in ACME).]
\n\n\avnameCFG\a [\aSUFFIX\a]
'
function prepareJWS_PH {
	typeset -n CFG=$1
	getPrivateKey CFG || return $?
	typeset SZ MODULUS EXP PUB CURVE A B R S V KD JWK SFX
	integer L
	
	[[ -n $2 ]] && SFX="$2" || SFX=
	# no kid needed for '-NEW'
	[[ ${SFX} == '-NEW' && -n ${CFG["JWS-PH-JWK${SFX}"]} ]] && return 0
	# else wanna both
	[[ -n ${CFG["JWS-PH-JWK${SFX}"]} && -n ${CFG["JWS-PH-KID${SFX}"]} ]] && \
		return 0

	KD=${CFG[KEY-DESC${SFX}]}
	if [[ ! ${KD} =~ NIST\ CURVE:\ P-|modulus:.*publicExponent:.* ]]; then
		Log.fatal 'Unsupported private key!'
		return 1
	fi
	if (( VERB )); then
		[[ -z ${SFX} ]] && Log.info 'Preparing JWS protected headers ...' || \
			Log.info 'Preparing JWS protected headers for the new key ...'
	fi

	# parse in the key parameters
	print -- "${KD}" | while read A B ; do
		[[ ${A:0:3} == {2}([0-9a-f])* ]] && S+="$A" && continue
		[[ -n $V ]] && typeset -n R=$V && R="$S" && V=
		if [[ $A == 'Private-Key:' ]]; then
			SZ=${B:1}
			SZ=${SZ% *}
			V=
		elif [[ $A == 'pub:' ]]; then
			V=PUB S=
		elif [[ $A == 'NIST' ]]; then
			CURVE=${B##* }
			V=
		elif [[ $A == 'modulus:' ]]; then
			V=MODULUS S=
		elif [[ $A == 'publicExponent:' ]]; then
			S=${B##*x} V=
			# re-format as hexdump
			(( ${#S} % 2 )) && S=${S%\)} || S=0${S%\)}
			for (( L=0; L < ${#S}; L+=2 )); do
				V+=":${S:L:2}"
			done
			EXP="${V:1}" V= S= 
			V=
		fi
	done
	unset -n R

	# prepare JWK, PH
	if [[ -n ${CURVE} && ${CURVE:0:2} == 'P-' && \
		-n ${PUB} && ${PUB:0:3} == '04:' ]]
	then
		SZ=${CURVE:2}
		# only uncompressed keys (i.e. neither compressed nor hybrid)
		V=${PUB:3}			# get rid off the type decription byte
		hexdump2str V || return 2

		(( L = ${#V} / 2 ))
		A="${V:0:L}"
		str2base64url CFG A 1 || return 3
		B=${V:L}
		str2base64url CFG B 1 || return 4

		V=
		JSON.newString L 'EC' && return  5 || V+=" kty $L"
		JSON.newString L "${CURVE}" && return  6 || V+=" crv $L"
		JSON.newString L "$A" && return  7 || V+="  x $L"
		JSON.newString L "$B" && return  8 || V+="  y $L"
		JSON.newString L "ES${SZ}" && return 9 || CFG["PH-ALG${SFX}"]=$L
	elif [[ -n ${MODULUS} && -n ${EXP} ]]; then
		A=${EXP}
		hexdump2str A || return 10
		str2base64url CFG A 1 || return 11 
		# rfc7518 6.3.1.1. note
		[[ ${MODULUS:0:3} == '00:' ]] && B=${MODULUS:3} || B=${MODULUS}
		hexdump2str B || return 12
		str2base64url CFG B 1 || return 13

		V=
		JSON.newString L 'RSA' && return  14 || V="kty $L"
		JSON.newString L "$A" && return  15 || V+=" e $L"
		JSON.newString L "$B" && return  16 || V+=" n $L"
		S=${CFG[KEY_TYP_ACC]:-RSA256-2048}
		[[ $S == RSA@(256|384|512)-+([0-9]) ]] && S=${S:3:3} || \
			{ Log.info 'Invalid KEY_TYP_ACC - falling back to RSA256'; S=256; }
		JSON.newString L "RS$S" && return 17 || CFG["PH-ALG${SFX}"]=$L
	else
		Log.fatal 'Unable to extract required parameters from private key'
		return 18
	fi
	JSON.newObject JWK
	JSON.setVal ${JWK} $V && CFG["PH-JWK${SFX}"]=${JWK} || return 20

	JSON.newString L 'unset' && return 21 || CFG["PH-NONCE${SFX}"]=$L
	JSON.newString L 'unset' && return 22 || CFG["PH-URL${SFX}"]=$L
	JSON.newString L 'unset' && return 23 || CFG["PH-KID${SFX}"]=$L
	JSON.newObject L
	# Boulder Section 6.3.1 - ignores 'url' required by ACME
	if [[ ${SFX} != '-NEW' ]]; then
		JSON.setVal $L alg ${CFG["PH-ALG${SFX}"]} jwk ${JWK} \
			nonce ${CFG["PH-NONCE${SFX}"]} url ${CFG["PH-URL${SFX}"]} || \
			return 24
	else
		JSON.setVal $L alg ${CFG["PH-ALG${SFX}"]} jwk ${JWK} \
			url ${CFG["PH-URL${SFX}"]} || return 24			# change key jwk
	fi
	# Boulder Section 6.2 - enforces 'jwk' field
	CFG["JWS-PH-JWK${SFX}"]=$L

	if [[ ${SFX} != '-NEW' ]]; then		# only for non-key change requests
		JSON.newObject L
		JSON.setVal $L alg ${CFG["PH-ALG${SFX}"]} kid ${CFG["PH-KID${SFX}"]} \
			nonce ${CFG["PH-NONCE${SFX}"]} url ${CFG["PH-URL${SFX}"]} || \
			return 25
		CFG["JWS-PH-KID${SFX}"]=$L	# ACME
	fi
	if (( VERB )); then
		A= B=
		JSON.toString ${CFG["JWS-PH-JWK${SFX}"]} A
		JSON.toString ${CFG["JWS-PH-KID${SFX}"]} B
		Log.info "done:\n\t$A\n\t$B"
	fi
	return 0
}

Man.addFunc sign '' '[+NAME?sign - sign an arbitrary string]
[+DESCRIPTION?Uses the key \avnameCFG\a[KEY\aSUFFIX\a] to sign the value of \avnameTXT\a and stores the signature as a colon separated hex byte string into \avnameSIG\a. If an account key has not been setup up, it gets automatically created according to \avnameCFG\a. In the latter case this function uses the related config keys suffixed with a \b-NEW\b as described in \bprepareJWS_PH()\b.]
\n\n\avnameCFG\a \avnameTXT\a \avnameSIG\a [\aSUFFIX\a]
'
function sign {
	typeset -n CFG=$1 TXT=$2 SIG=$3
	typeset ALG OUT X SFX="$4"

	# If we wanna sign something, we need sooner or later the JWS-PH. So
	# prepare it, which gives us also CFG[PH-ALG] and all the key stuff
	prepareJWS_PH CFG "${SFX}" || return 1
	JSON.getVal ${CFG["PH-ALG${SFX}"]} ALG
	print -r -- "${CFG[KEY${SFX}]}" >${LE_TMP}/akey	# call it paranoid ;-)

	# We use the colon separated hex output for reason, even if it introduces
	# some add. steps when it gtes finally converted to base64url
	if [[ ${ALG:0:2} == 'RS' ]]; then
		X=( ${ print -rn -- "${TXT}" | \
			${CFG[OPENSSL]} dgst -sign ${LE_TMP}/akey -sha${ALG:2} -hex -c ; } )
		# openssl >= 1.x emits a 'stdin= ' prefix
		[[ ${X:2:1} == ':' ]] && SIG=$X || SIG=${X[1]}
	else
		# ES: concat R & S
		typeset IFS=$'\n:'
		X=( ${ print -rn -- "${TXT}" | \
			${CFG[OPENSSL]} dgst -sign ${LE_TMP}/akey -sha${ALG:2} | \
			${CFG[OPENSSL]} asn1parse -inform DER; } )
		OUT="${X[6]}${X[10]}"
		integer I
		X=
		for (( I=0; I < ${#OUT}; I+=2 )); do
			X+=":${OUT:I:2}"
		done
		SIG=${X:1}
	fi
	[[ -n ${SIG} ]]
}

Man.addFunc createSig '' '[+NAME?createSig - create a base64url encoded signature.]
[+DESCRIPTION?Small wrapper around \bsign()\b, which creates a signature from the given base64url encoded \aprotected\a header and the payload passed via \avnamePL\a as an unencoded string. \aSUFFIX\a (if given) gets passed as is to \bsign()\b. The created signature gets stored into \avnameSIG\a. On success \avnamePL\a will contain the base64url encoded value of the payload.]
\n\n\avnameCFG\a \avnameSIG\a \avnamePL\a \aprotected\a [\aSUFFIX\a]
'
function createSig {
	typeset -n CFG=$1 SIG=$2 PL=$3
	typeset PH="$4" SFX="$5"

	(( VERB )) && Log.info "Signing payload '${PL}' ..."
	SIG=
	str2base64url CFG PL || return 1
	V="${PH}.${PL}"
	sign CFG V SIG ${SFX} || return 2
	hexdump2str SIG || return 3
	str2base64url CFG SIG 1 || return 4
}

Man.addFunc checkEmailAddr '' '[+NAME?checkEmailAddr - check, whether we accept the given e-mail address.]
[+DESCRIPTION?A more or less simple check, whether the given e-mail \aaddress\a is allowed by this script. The check is basically made wrt. RFC 2822, but exclude some more characters to avoid trouble or special treatment.]
\n\n\aaddress\a
'
function checkEmailAddr {
	[[ -z  $1 ]] && return 1
	typeset ADDR="$1" LOCAL DOM SUBS
	integer L

	LOCAL="${ADDR%%@*}"
	DOM="${.sh.match:1}"
	[[ -z ${DOM} ]] && return 3
	# in add. to RFC 2822 we exclude the chars: ! # $ % & ' * / = ? ^ ` { | } 
	# which are allowed, but may cause trouble or would need special treatment
	# like escaping (see RFC 6068). Also ACME prohibits hfields or more than a
	# single address.
	[[ ${LOCAL} =~ ^[-a-zA-Z0-9+_~]+(\.[-a-zA-Z0-9+_~]+)*$ ]] || return 4
	[[ ${DOM} =~ ^[-a-zA-Z0-9+_~]+(\.[-a-zA-Z0-9+_~]+)*$ ]] || return 5
	(( ${#DOM} > 255 )) && return 6
	# domain parts
	SUBS=( ${DOM//./ } )
	(( L = ${#SUBS[@]} - 1 ))
	(( L <  1 || ${#SUBS[L]} < 2 || ${#SUBS[L-1]} < 2 )) &&  return 7
	for (( ; L >= 0; L-- )); do
		(( ${#SUBS[L]} > 64 )) && return 8
		[[ ${SUBS[L]} =~ ^[a-zA-Z0-9]+(-+[a-zA-Z0-9]+)*$ ]] || return 9
	done
	# no IPs
	[[ ${DOM} =~ [0-9]+$ || ${DOM} =~ ^[0-9]+(\.[0-9]+)*$ ]] && return 10
	return 0
}

Man.addFunc checkAccountUrl '' '[+NAME?checkAccountUrl - test and read in an account url file.]
[+DESCRIPTION?Read in the \avnameCFG\a\b[ACCOUNT-URL-FILE]]\b file and store its content to  \avnameCFG\a\b[ACCOUNT-URL]]\b. If the file does not exist or is empty, an error message gets emitted. If it contains invalid contents, i.e. not a valid or unrelated URL, the consumer of this value needs to deal with it.]
\n\n\avnameCFG\a
'
function checkAccountUrl {
	typeset -n CFG=$1
	typeset FILE="${CFG[ACCOUNT-URL-FILE]}"

	[[ -z ${CFG[ACCOUNT-URL]} && -e ${FILE} ]] && CFG[ACCOUNT-URL]=$(<"${FILE}")
	if [[ -z ${CFG[ACCOUNT-URL]} ]]; then
		Log.fatal \
"\n\tFile '${ACC_FILE}' cannot be read or is empty!" \
"\n\tThis file is required for further ACME operations. You may re-create it" \
"\n\tby running the 'register' command (again)."
		return 1
	fi
	return 0
}

Man.addFunc checkEmail '' '[+NAME?checkEmail - check current e-mail setting.]
[+DESCRIPTION?Check whether \avnameCFG\a\b[EMAIL]]\b is set. If not, emit an error message and return immediately. Otherwise, if its value is not equal to a dash (\b-\b), check whether we allow it wrt. ACME requirements and syntax (see \bcheckEmailAddr()\b).]
\n\n\avnameCFG\a
'
function checkEmail {
	typeset -n CFG=$1
	if [[ -z ${CFG[EMAIL]} ]]; then
		Log.fatal 'e-mail address is required.'
		return 1
	elif [[ ${CFG[EMAIL]} != '-' ]]; then
		# fail early
		if ! checkEmailAddr "${CFG[EMAIL]}"; then
			Log.fatal "The e-mail address '${CFG[EMAIL]}' is invalid or" \
				'contains unsupported characters.'
			return 2
		fi
	fi
	return 0
}

Man.addFunc shaHash '' '[+NAME?shaHash - SHA hash a given input.]
[+DESCRIPTION?This function hashes the value stored in \avname\a using SHA with the given \asize\a. On success the digest gets stored as groups of two hex digits separated by colons into \avname\a and thus overwrites the input. If no \asize\a is given, 256 will be used instead.]
\n\n\avname\a \asize\a
'
function shaHash {
	typeset -n CFG=$1 IN=$2
	typeset OUT N=$3
	
	[[ -z $N ]] && N=256
	OUT=${ print -n -- "${IN}" | \
		${CFG[OPENSSL]} dgst -sha$N -hex -c 2>/dev/null; }
	[[ -z ${OUT} ]] && return 1		# should not happen
	IN="${OUT#*= }"
	return 0
}

Man.addFunc accountPrepareRequest '' '[+NAME?accountPrepareRequest - prepare account related HTTP requests.]
[+DESCRIPTION?This function handles the account related management. \avnameCFG\a contains the current configuration related to the \bACCOUNT\a and \bCA-NAME\b to use. \avnamePARAMS\a is the name of the assocaitive array, which gets finally passed to \bfetch()\b. This function sets certain parameters so that fetch does, what is needed (e.g. setting the type of http method to use and data to post). \aTYPE\a finally tells, what kind of request needs to be constructed. For now the following are defined:]{
	[+CREATE?Try to register a new account.]
	[+FIND?Find the account URL for a given account/key.]
	[+UPDATE?Update the contact information of an account.]
	[+INFO?Fetch information for an account.]
	[+BIND?Unsupported.]
	[+CHKEY?Change the public key of an account.]
	[+CLOSE?Deactivate the account.]
}
[+?The following function get called as needed: \bcheckAccountUrl()\b, \bcheckEmail\b(), \bgetNonce()\b, \bprepareJWS_PH()\b, \bsign()\b, which try to obtain all additional information and to store them into the current configuration if appropriate - no need to do it manually before.]
\n\n\avnameCFG\a \avnamePARAMS\a \aTYPE\a
'
function accountPrepareRequest {
	typeset -n CFG=$1 PARAMS=$2
	typeset PH PL T URL V SFX=
	integer L CMD

	case "${3:-CREATE}" in
		CREATE) CMD=0 ;;		# 7.3.0
		FIND) CMD=1 ;;			# 7.3.1
		UPDATE) CMD=2 ;;		# 7.3.2
		INFO) CMD=3 ;;			# 7.3.3
#		BIND) CMD=4 ;;			# 7.3.5		no known ext. servers		
		CHKEY) CMD=5 ;;			# 7.3.6
		CLOSE) CMD=6 ;;			# 7.3.7
		*) Log.fatal "Unsupported account sub command '$2'."; return 1 ;;
	esac

	(( CMD > 1 )) && { checkAccountUrl CFG || return 2; }
	(( CMD == 0 || CMD == 2 )) && { checkEmail CFG || return 3 ; }

	getNonce CFG || return 4
	typeset -n DIRKEY=${CFG[DIR-KEY]}

	# Boulder does not support 'only-return-existing' (7.3.1)
	(( CMD == 1 && CFG[IS_LE] )) && CMD=0

	if (( CMD < 2  || CMD == 4 )); then
		URL="${CFG[URL-account]}"
	elif (( CMD < 4 || CMD == 6 )); then
		URL="${CFG[ACCOUNT-URL]}"
	elif (( CMD == 5 )); then
		URL="${CFG[URL-chkey]}"
	fi
	[[ -z ${URL} ]] && return 5	# should not happen

	(( CMD < 2 || CMD == 5 )) && V=1 || V=		# force JWK
	prepareDefaultPH CFG PH "${URL}" $V || return 11

	# payload
	V=
	if (( CFG[IS_LE] )) ; then
	# 7.1
		if (( CMD == 0 )); then
			JSON.newString L "${DIRKEY[account]}" && return 21
			V+=" resource $L"
			JSON.newString L "${CFG[URL-tos]}" && return 21
			V+=" agreement $L"
		elif (( CMD == 2 || CMD == 3 || CMD == 6 )); then
			JSON.newString L "reg" && return 22
			V+=" resource $L"
			if (( CMD == 2 )); then
				JSON.newString L "${CFG[URL-tos]}" && return 22
				V+=" agreement $L"
			fi
		elif (( CMD == 5 )); then
			# Boulder Section 7.3.6
			JSON.newString L "${DIRKEY[chkey]}" && return 23
			V+=" resource $L"
		fi
	fi
	if (( CMD == 6 )); then
		JSON.newString L 'deactivated' && return 24
		V+=" status $L"
	elif (( CMD == 5 )); then
		typeset PHN PLN S SFX='-NEW'
		prepareJWS_PH CFG "${SFX}" || return 24
		JSON.setVal ${CFG["PH-URL${SFX}"]} "${URL}" || return 25
		JSON.toString ${CFG["JWS-PH-JWK${SFX}"]} PHN || return 26
		(( VERB )) && Log.info "The payload JWS header:\n${PHN}"
		str2base64url CFG PHN || return 27

		JSON.newString L "${CFG[ACCOUNT-URL]}" && return 27
		JSON.newObject T && return 28
		JSON.setVal $T 'account' $L 'newKey' ${CFG[PH-JWK-NEW]} || return 29
		JSON.toString $T PLN || return 30

		createSig CFG S PLN "${PHN}" ${SFX} || return 30

		JSON.newString L "${PHN}" && return 35 || V+=" protected $L"
		JSON.newString L "${PLN}" && return 36 || V+=" payload $L"
		JSON.newString L "$S" && return 37 || V+=" signature $L"
	elif (( CMD == 0 || CMD == 2 )); then
		# 7.3
		if [[ ${CFG[EMAIL]} != '-' ]]; then
			# Boulder Section 7.3 - only mailto
			JSON.newString L "mailto:${CFG[EMAIL]}" && return 23
			JSON.newArray T && return 24
			JSON.setVal $T $L || return 12	# that's all, what boulder supports
			V+=" contact $T"
		elif (( CMD == 2 )) && [[ ${CFG[EMAIL]} == '-' ]] ; then
			JSON.newArray T && return 11
			V+=" contact $T"
		fi
		if [[ -n ${CFG[TOS]} ]]; then
			JSON.newTrue L && return 13
			V+=" ${DIRKEY[tos]} $L"
		fi
	elif (( CMD == 1 )); then
		JSON.newTrue L && return 15
		V+=" ${DIRKEY[existing]} $L"
	fi
	JSON.newObject L && return 16
	JSON.setVal $L $V || return 17
	JSON.toString $L PL || return 18

	createSig CFG T PL "${PH}" || return 20

	newRequestBody T "${PH}" "${PL}" "$T" || return 30
	(( VERB )) && Log.info "Sending account request\n\t$T"

	PARAMS=(
		[URL]="${URL}" [METHOD]='POST' [DATA]="$T" [DUMP]="${URL##*/}-${CMD}" )
}

Man.addFunc newRequestBody '' '[+NAME?newRequestBody - create a new ACME request body.]
[+DESCRIPTION?Create a new ACME request body and store it as string into \avnameBody\a. \aprotected\a, \apayload\a and \asignature\a are the values for the corresponding fields, and used as is, so usually they should be base64url encoded.]
\n\n\avnameBody\a \aprotected\a \apayload\a \asignature\a
'
function newRequestBody {
	typeset -n S=$1
	typeset PH="$2" PL="$3" SIG="$4" V
	integer L

	S=
	JSON.newString L "${PH}" && return 1 || V=" protected $L"
	JSON.newString L "${PL}" && return 2 || V+=" payload $L"
	JSON.newString L "${SIG}" && return 3 || V+=" signature $L"
	JSON.newObject L && return 4
	JSON.setVal $L $V || return 5
	JSON.toString $L S || return 6
	(( VERB )) && Log.info "Request body:\n$S"
	return 0
}

# 7.3.4
# 7.4.1
Man.addFunc check403 '' '[+NAME?check403 - check for 403 server response (7.3.4, 7.4.1)]
[+DESCRIPTION?Check the response (\avnameRES\a\b[BODY]]\b) of the server for status code \b403\b and deserialize the \bproblem+json\b content if available. The entries of each deserialized key: value pair gets stored in \avnameRES\a whereby the key alias JSON property name gets prefixed a \b_RES_\b (i.e. \b_RES_type\b, \b_RES_detail\b, \b_RES_instance\b, etc.). Finally, if the \avnameRES\a\b[STATUS_CODE]]\b is \b403\b, an appropriate error message gets emitted to stderr and the function returns with \b0\b. Otherwise the function silently returns with the \avnameRES\a\b[STATUS_CODE]]\b.]
\n\n\avnameRES\a
'
function check403 {
	typeset -n R=$1			# the fetch result
	L=0 V= X=

	# first unserialize problem report
	if [[ ${R[Content-Type]} == 'application/problem+json' ]]; then
		print -rn -- "${R[BODY]}" | JSONP.readValue L V
		if (( L )); then
			typeset -A PROPS
			JSON.getVal $L PROPS
			for X in ${!PROPS[@]} ; do
				if JSON.isObject ${PROPS["$X"]} ; then
					R[_RES_"$X"]=${PROPS["$X"]}
				else
					JSON.getVal ${PROPS["$X"]} V
					R[_RES_"$X"]="$V"
				fi
			done
		fi
	fi

	if (( R[STATUS_CODE] == 403 )); then
		X='Server response: The requested operation is currently forbidden.'
		# see also Boulder Section 6.5 .. Section 6.6
		[[ -n ${R[_RES_detail]} ]] && X+=" ${R[_RES_detail]}."
		[[ -n ${R[_RES_instance]} ]] && X+=" See also '${R[_RES_instance]}'."
		if [[ -n ${R[_RES_subproblems]} ]] ; then
			V=
			JSON.toStringPretty ${R[_RES_subproblems]} V
			[[ -n $V ]] && X+="\n\tDetails:\n$V"
		fi
		Log.fatal "$X"
		return 0
	fi
	(( R[STATUS_CODE] == 0 )) && return 1
	return ${R[STATUS_CODE]}
}

Man.addFunc updateAccountURL '' '[+NAME?updateAccountURL - update the related account url file by server response.]
[+DESCRIPTION?Analyze the http resonse \avnameRES\a (see \bfetch()\b) for a [Content-]]Location header entry and update the contents of the account URL file as well as \avnameCFG\a\b[ACCOUNT-URL]]\b with its value aka account URL, if available. If n/a an error message gets emitted and the function returns with 1.]  
\n\n\avnameCFG\a \aavnameRES\a
'
function updateAccountURL {
	typeset -n CFG=$1 RESULT=$2
	typeset V="${RESULT[Location]}"
	[[ -z $V ]] && V="${RESULT[Content-Location]}"	# boulder
	if [[ -z $V ]]; then
		Log.fatal 'Unexpected server response - no Location header.'
		return 1
	fi
	(( VERB )) && Log.info "Account URL is '$V'."
	print -- "${RESULT[Location]}" >"${CFG[ACCOUNT-URL-FILE]}"
	CFG[ACCOUNT-URL]="$V"
}

# 7.3.0
Man.addFunc accountCreate '' '[+NAME?accountCreate - register a new account (7.3.0).]
[+DESCRIPTION?Registers the account \avnameCFG\a\b[ACCOUNT]]\b via \avnameCFG\a\b[CA-NAME]]\b. All required CFG parameters are determined/obtained as needed on the-fly.]
\n\n\avnameCFG\a
'
function accountCreate {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS

	(( VERB )) && Log.info "Trying to register account '${CFG[ACCOUNT]}'..."
	accountPrepareRequest CFG PARAMS CREATE || return 2
	fetch CFG RESULT PARAMS || return 3
	check403 RESULT && return 4
	
	integer SC=${RESULT[STATUS_CODE]}
	# Boulder Section 7.3 -  uses 409 (Conflict) instead of 200 (OK)
	if (( SC == 201 || SC == 200 || SC == 409  )); then
		updateAccountURL CFG RESULT
		typeset V="${CFG[ACCOUNT]}"
		(( SC != 201 )) && Log.info "Account '$V' already exists." || \
			Log.info "New Account '$V' registered."
		return 0
	fi
	X="Registration of account '${CFG[ACCOUNT]}' failed"
	[[ ${RESULT[_RES_detail]} ]] && X+=" with '${RESULT[_RES_detail]}'"
	Log.fatal "${X}."
	return 1
}

# 7.3.1
Man.addFunc accountFind '' '[+NAME?accountFind - find the URL for an account (7.3.1).]
[+DESCRIPTION?Find the URL to use for the account \avnameCFG\a\b[ACCOUNT]]\b via \avnameCFG\a\b[CA-NAME]]\b. All required CFG parameters are determined/obtained as needed on the-fly. On success the contents of the related account URL file as well as \avnameCFG\a\b[ACCOUNT-URL]]\b get changed accordingly.]
\n\n\avnameCFG\a
'
function accountFind {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS
	typeset V

	Log.info "Trying to find account URL for '${CFG[ACCOUNT]}'..."
	accountPrepareRequest CFG PARAMS FIND || return 2
	fetch CFG RESULT PARAMS || return 3
	check403 RESULT && return 4

	integer SC=${RESULT[STATUS_CODE]}
	# because boulder does not support this, it gets turned into a CREATE req
	if (( CFG[IS_LE] )); then
		V="${CFG[ACCOUNT]}"
		if (( SC == 201 || SC == 409 )); then
			(( SC == 201 )) && Log.info "Ooops - new account '$V' registered."
			VERB=1 updateAccountURL CFG RESULT
			return $?
		fi
	fi
	# acme
	if (( SC == 200 )); then
		VERB=1 updateAccountURL CFG RESULT
		return  $?
	fi
	if (( SC == 400 )); then
		Log.info "Account '${CFG[ACCOUNT]}' does not exist."
		return 0
	fi
	if [[ -n ${RESULT[_RES__detail]} ]]; then
		Log.fatal "Account URL find failed with '${RESULT[_RES__detail]}'."
	elif [[ -n ${RESULT[STATUS_TXT]} ]]; then
		Log.fatal 'Account URL find failed with status' \
			"${RESULT[STATUS_CODE]}: '${RESULT[STATUS_TXT]}'."
	else
		Log.fatal 'Account URL find failed.'
	fi
	return 1
}

# 7.3.2
Man.addFunc accountUpdate '' '[+NAME?accountUpdate - update the contact information of an account (7.3.2).]
[+DESCRIPTION?Update the contact information for the account \avnameCFG\a\b[ACCOUNT]]\b via \avnameCFG\a\b[CA-NAME]]\b. All required CFG parameters are determined/obtained as needed on the-fly. If \avnameCFG\a\b[EMAIL]]\b is not set, an error message gets emitted and the function returns immediately with 1. To remove the e-mail address from contact information, use a single dash (-) as address. Otherwise the function returns as usual with 0 on success, or a value > 1 otherwise.]
\n\n\avnameCFG\a
'
function accountUpdate {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS

	accountPrepareRequest CFG PARAMS UPDATE || return 2
	fetch CFG RESULT PARAMS || return 3
	check403 RESULT && return 4

	integer SC=${RESULT[STATUS_CODE]}
	typeset X="Contact information update for account '${CFG[ACCOUNT]}'"
	if (( SC == 200 || SC == 202 )); then
		Log.info "$X  succeeded."
		return 0
	fi
	X+=' failed'
	[[ -n ${RESULT[_RES_detail]} ]] && X+=" with '${RESULT[_RES_detail]}'"
	Log.fatal "${X}."
	return 5
}

# 7.3.3
Man.addFunc accountInfo '' '[+NAME?accountInfo - get information about an account (7.3.3).]
[+DESCRIPTION?Queries the server \avnameCFG\a\b[CA-NAME]]\b for information about the account \avnameCFG\a\b[ACCOUNT]]\b. All required CFG parameters are determined/obtained as needed on the-fly.]
\n\n\avnameCFG\a
'
function accountInfo {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS

	(( VERB )) && Log.info "Getting infos for account '${CFG[ACCOUNT]}'..."
	accountPrepareRequest CFG PARAMS INFO || return 2
	fetch CFG RESULT PARAMS || return 3
	check403 RESULT && return 4

	if (( RESULT[STATUS_CODE] == 200 || RESULT[STATUS_CODE] == 202 )); then
		# Boulder Section 7.1.2 - no TOS or orders field. Anyway, just dump:
		typeset X L V
		print -rn -- "${RESULT[BODY]}" | JSONP.readValue L V
		V=
		JSON.toStringPretty $L X V '    '
		Log.info "Server information for account '${CFG[ACCOUNT]}':\n$X"
		return 0
	fi
	X="Getting server information for account '${CFG[ACCOUNT]}' failed"
	[[ ${RESULT[_RES_detail]} ]] && X+=" with '${RESULT[_RES_detail]}'"
	Log.fatal "${X}."
	return 5
}

Man.addFunc listAccounts '' '[+NAME?listAccounts - list all ACME accounts.]
[+DESCRIPTION?Print out the name of all local accounts. It just scans the current config directory for a-*.key files and strips off its prefix and suffix.]
\n\n\avnameCFG\a
'
function listAccounts {
	typeset -n CFG=$1
	typeset X F

	[[ -d ${CFG[CFG-DIR]} ]] || return 0
	cd ${CFG[CFG-DIR]}
	X=
	for F in ~(N)a-*.key ; do
		[[ -n $F ]] && X+=" ${F:2:${#F}-6}"
	done
	[[ -z $X ]] && return 0
	print 'Accounts: ' $X
}


# 7.3.5  TBD: External Account Binding (EAB)
#	- for now (Dec. 2017) no test information available
#	- RFC idea: use key ID (kid) and hmac from an external CA for registration
#	- e.g. https://github.com/xenolf/lego/commit/5115a955b24d26ee9bd13135e709aed7d79751c5

Man.addFunc recyclePath '' '[+NAME?recyclePath - backup the given path in a cyclic manner.]
[+DESCRIPTION?Rename the given \apath\a to \apath\a\b.old-\b\aN\a, whereby \aN\a is the formatted number \b0\b. On success this name gets stored into \avname\a. All previous "copies" which match the given pattern with N={0..9} get renamed to \apath\a\b.old-\b\a$((N-1))\a. Note that this function does not take the file type into account, so directory name is a valid parameter/pattern match as well!]
\n\n\avname\a \apath\a
'
function recyclePath {
	[[ -z $1 || -z $2 ]] && return 0
	[[ -e $2 ]] || return 0

	typeset -n NEWNAME=$1
	typeset F="$2" S T FMT='%02d'
	integer I K=8

	for (( I=K+1; I > 0; I--,K-- )); do
		T=${ printf "${FMT}" $K ; }
		[[ -e ${F}.old-$T ]] || continue
		S=${ printf "${FMT}" $I ; }
		rm -rf "${F}.old-$S"			# no AI testing - contains '.old' ...
		mv "${F}.old-$T" "${F}.old-$S"	# and therefore ignore errors
	done
	T=${ printf "${FMT}" 0 ; }
	mv "${F}" "${F}.old-$T" && NEWNAME="${F}.old-$T" && return 0
	Log.warn "Unable to rename '${F}' to '${F}.old-$T'!"
	return 1
}

# 7.3.6
Man.addFunc accountChangeKey '' '[+NAME?accountChangeKey - replace the account key (7.3.6).]
[+DESCRIPTION?Replace the key of account \avnameCFG\a\b[ACCOUNT]]\b with the key in the file given via CLI or options file. If no file has been given, a new key gets generated using the \bKEY_TYP_ACC\b settings of the current config. In turn the new public key get submitted to the related ACME server. If accepted the local private keyfile gets changed accordingly, otherwise it stays as is. On success the values of \bKEY-DESC\b and \bKEY\b in the current config are the new ones.]
[+?All required CFG parameters are determined/obtained as needed on the-fly.]
\n\n\avnameCFG\a
'
function accountChangeKey {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS
	typeset NEWFILE="${LE_TMP}/newkey" FILE OLD
	
	if [[ -n ${CFG[NEWKEY]} ]]; then
		if ! cp "${CFG[NEWKEY]}" ${NEWFILE} ; then
			Log.fatal "Unable to copy new key from '${CFG[NEWKEY]}'"
			return 1
		fi
		KEY=${ ${CFG[OPENSSL]} pkey -noout -text -in ${NEWFILE} ; }
		if [[ -z ${KEY} || ${KEY:0:12} != 'Private-Key:' ]]; then
			Log.fatal "Unable to use the new private key in '${CFG[NEWKEY]}'." 
			return 2
		fi
		getPrivateKey CFG || return 3
		if [[ ${CFG[KEY-DESC]} == ${KEY} ]]; then
			Log.info 'The new private key to use is the same as the current' \
				'private key currently in use. Keeping it as is.'
			return 0
		fi
	else
		getPrivateKey CFG || return 4
		createPrivateKey CFG ${NEWFILE} ${CFG[KEY_TYP_ACC]} || return 5
		KEY=${ ${CFG[OPENSSL]} pkey -noout -text -in ${NEWFILE} ; }
	fi
	CFG[KEY-DESC-NEW]="${KEY}"
	CFG[KEY-NEW]=${ ${CFG[OPENSSL]} pkey -in ${NEWFILE} ; }	# clean up
	rm -f ${NEWFILE}

	getKeyFilename CFG FILE || return 6

	# fail early
	mv "${FILE}" "${FILE}.tmp" || return 7
	if ! cp -p "${FILE}.tmp" "${FILE}" ; then
		mv "${FILE}.tmp" "${FILE}" || { Log.fatal "Unable to mv '${FILE}.tmp'" \
			"to '${FILE}'!. Do this manually NOW! Otherwise chances are high," \
			'that you will loose use your private key on the next change key' \
			'operation and thus also loose access to your account.'; return 8; }
		Log.fatal 'Unable to create a new keyfile. Keeping stuff as is.'
	fi
	trap "rm -f ${FILE}.tmp" EXIT

	# now LE stuff
	(( VERB )) && Log.info "Changing pub key for account '${CFG[ACCOUNT]}'..."
	accountPrepareRequest CFG PARAMS CHKEY || return 9
	fetch CFG RESULT PARAMS || return 10
	check403 RESULT && return 11

	if (( RESULT[STATUS_CODE] == 409 )); then
		Log.warn 'The new key is already assigned to an existing account.' \
			'Keeping the current one as is.'
		return 12
	fi
	if (( RESULT[STATUS_CODE] != 200 )); then
		X='Account key roll-over failed'
		[[ ${RESULT[_RES_detail]} ]] && X+=" with '${RESULT[_RES_detail]}'"
		Log.fatal "${X}."
		return 13
	fi

	# on success
	recyclePath OLD "${FILE}" || return 14
	print -n "${KEY_WARNING}${CFG[KEY-NEW]}" >"${FILE}" || return 15
	chmod 0600 "${FILE}"
	(( VERB )) && Log.info "Done (${FILE}, backup: ${OLD})."
	# just make sure, other functions do not use cached values
	CFG[KEY-DESC]="${CFG[KEY-DESC-NEW]}" CFG[KEY]="${CFG[KEY-NEW]}"
	CFG[KEY-DESC-NEW]= CFG[KEY-NEW]= CFG[KEY-PUB]= CFG[NEWKEY]=
	CFG[JWS-PH-JWK-NEW]= CFG[JWS-PH-KID-NEW]=
	CFG[JWS-PH-JWK]= CFG[JWS-PH-KID]=
	return 0
}

# 7.3.7
Man.addFunc accountClose '' '[+NAME?accountClose - close the account (7.3.7).]
[+DESCRIPTION?Close the account \avnameCFG\a\b[ACCOUNT]]\b. If accepted the local private keyfile gets removed, otherwise it stays as is. On success the values of \bKEY-DESC\b and \bKEY\b in the current config are empty.]
[+?All required CFG parameters are determined/obtained as needed on the-fly.]
\n\n\avnameCFG\a
'
function accountClose {
	typeset -n CFG=$1
	typeset -A RESULT PARAMS
	typeset FILE

	accountPrepareRequest CFG PARAMS CLOSE || return 2
	getKeyFilename CFG FILE || return 3		# fail early
	fetch CFG RESULT PARAMS || return 4
	check403 RESULT && return 5
	
	if (( RESULT[STATUS_CODE] == 200 )); then
		Log.info "Account '${CFG[ACCOUNT]}' closed."
		recyclePath OLD "${FILE}"
		if [[ -n ${OLD} ]]; then
			Log.info "Private key has been moved to ${OLD}."
			mv "${FILE%.key}.url" "${FILE%.key}.url.${OLD##*.}"
		else
			rm -f "${FILE%.key}.url"
		fi
		CFG[KEY-DESC]= CFG[KEY]= CFG[JWS-PH-JWK]= CFG[JWS-PH-KID]=
		return 0
	fi
	typeset X="Closing account '${CFG[ACCOUNT]}'  failed"
	[[ -n ${RESULT[_RES_detail]} ]] && X+=" with '${RESULT[_RES_detail]}'"
	Log.fatal "${X}."
	return 6
}

Man.addFunc checkDomainSyntax '' '[+NAME?checkDomainSyntax - simple domain syntax checker.]
[+DESCRIPTION?Makes some simple syntax checks to make sure, that the given \adomain\a conforms to basic rules for domain names.]
\n\n\adomain\a
'
function checkDomainSyntax {
	[[ -z $1 ]] && return 1
	typeset X="$1" SUBS
	integer L

	if (( ${#X} > 255 )); then
		Log.fatal "Invalid domain '$X' (has more than 255 characters)."
		return 2
	fi
	SUBS=( ${X//./ } )
	(( L = ${#SUBS[@]} - 1 ))
	if (( L <  1 || ${#SUBS[L]} < 2 || ${#SUBS[L-1]} < 2 )) ; then
		Log.fatal "Invalid domain '$X'. Should have at least 2 parts" \
			'with 2 or more letters each.'
		return 3
	fi
	for (( ; L >= 0; L-- )); do
		if (( ${#SUBS[L]} > 64 )); then
			Log.fatal "Invalid domain '$X' ('${SUBS[L]}' has more than" \
				'64 characters).'
			return 4
		fi
		if [[ ! ${SUBS[L]} =~ ^[a-zA-Z0-9]+(-+[a-zA-Z0-9]+)*$ ]]; then
			Log.fatal "Invalid domain '$X' ('${SUBS[L]} contains invalid" \
				'characters - a-zA-Z0-9 and - or + not as the first' \
				'are allowed.'
			return 5
		fi
	done
	if [[ $X =~ [0-9]+$ || $X =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
		Log.fatal "Invalid domain '$X' (IPv4 like addresses are not" \
			' allowed.)'
		return 6
	fi
	# all other checks should be done by the server
	return 0
}

# 7.5
Man.addFunc getChallenges '' '[+NAME?getChallenges - extract a challenge and meta data from a JSON object]
[+DESCRIPTION?Extract/flatten the meta data and challenges from the JSON object given as normal text passed as value or file.  It should represent a \bnew-authz\b response from an ACME server. The extracted data get stored into the associative array named \avnameAUTHZ\a using the following key/value pairs:]{
	[+JID?The JSON object id containing the \bidentifier\b property.]
	[+ID_TYPE?The value of the \bidentifier.type\b property.]
	[+DOMAIN?The value of the \bidentifier.value\b property.]
	[+STATUS?The value of the \bstatus\b property.]
	[+EXPIRES?The \bexpires\b property value converted to seconds since the Epoch - see \bstrftime\b(3C) "%s".]
	[+EXPIRED?Contains \b0\b if expires is > NOW, \b1\b otherwise.]
	[+\aCTYPE_SHORT\a?The \aCTYPE\a.]
	[+\aCTYPE\a\b-status\b?The status of the challenge for \aCTYPE\a.]
	[+\aCTYPE\a\b-uri\b?The URI of the challenge for \aCTYPE\a.]
	[+\aCTYPE\a\b-token\b?The token of the challenge for \aCTYPE\a.]
	[+\berror-\b\akey\a?The value of the \berror.\b\akey\a property, if available.]
}
[+?\aCTYPE\a is the type of the challenge, usually one of \bhttp-01\b, \btls-sni-01\b, \bdns-01\b and rarely \boob\b and \aCTYPE_SHORT\a the common name for it, which is everything before the first dash in \aCTYPE\a, e.g. \bhttp\b, \btls\b, \bdns\b, or \boob\b.]
[+?If both arguments are given (file and string), the file gets parsed in, only.]
[f:file]:[path?The JSON file to read. If theres is no such file or it cannot be parsed, this function does nothing, but returning \b1\b instead of \b0\b.]
[s:string]:[text?The text representing the JSON object to read in. If it cannot be parsed, \b2\b gets returned instead off \b0\b.]
\n\n\avnameAUTHZ\a
'
function getChallenges {
	typeset -A PROPS
	integer L TIME NOW
	typeset A S TYPE FILE= TEXT=

	S="${ Man.funcUsage $0 ; }"
	while getopts "$S" option ; do
		case "${option}" in
			f) FILE="${OPTARG}" ;;
			s) TEXT="${OPTARG}" ;;
		esac
	done
	L=$((OPTIND-1))
	shift $L
	OPTIND=1
	typeset -n RES=$1
	[[ -n ${FILE} && -n ${TEXT} ]] && Log.warn "$0: SW bug - JS string ignored."
	[[ -z ${FILE} && -z ${TEXT} ]] && return 0

	S=
	if [[ -n ${FILE} ]]; then
		cat "${FILE}" | JSONP.readValue L S || return 1
	else
		print -rn -- "${TEXT}" | JSONP.readValue L S || return 2
	fi

	JSON.getVal $L PROPS
	if (( ${PROPS['identifier']} )) ; then
		RES[JID]=${PROPS['identifier']}
		typeset -A IDPROPS
		JSON.getVal ${RES[JID]} IDPROPS
		JSON.getVal ${IDPROPS['value']} S && RES[DOMAIN]="$S"
		JSON.getVal ${IDPROPS['type']} S && RES[ID_TYPE]="$S" && TYPE="$S"
	fi
	JSON.getVal ${PROPS['status']} S && RES[STATUS]="$S"
	if JSON.getVal ${PROPS['expires']} S ; then
		RES[EXPIRES]=${ printf '%(%s)T' "$S" ; }
		unset NLSPATH		# avoid that ksh93 picks up e.g. the 'share' binary
		NOW=${ printf '%(%s)T' now ; }
		(( NOW < RES[EXPIRES] )) && RES[EXPIRED]=0 || RES[EXPIRED]=1
	fi
	if (( ${PROPS['error']} )) ; then 
		typeset -A E
		JSON.getVal ${PROPS['error']} E
		for A in ${!E[@]} ; do
			JSON.getVal ${E["$A"]} S && RES["error-$A"]="$S"
		done
	fi

	# challenge object as response to a challenge response request trigger
	# v04 6.5.1 ...: "The server provides a 200 (OK) response with the updated
	# challenge object as its body."
	JSON.getVal ${PROPS['type']} TYPE && RES[${TYPE%%-*}]="${TYPE}"
	JSON.getVal ${PROPS['status']} S && RES["${TYPE}-status"]="$S"
	JSON.getVal ${PROPS['validated']} S && RES["${TYPE}-validated"]="$S"
	JSON.getVal ${PROPS['keyAuthorization']} S && \
		RES["${TYPE}-keyAuthorization"]="$S"
	# contained in status queries
	JSON.getVal ${PROPS['uri']} S && RES["${TYPE}-uri"]="$S"
	JSON.getVal ${PROPS['token']} S && RES["${TYPE}-token"]="$S"

	# challenge objects of a new-authz response
	JSON.getVal ${PROPS['challenges']} A || return 0
	for S in $A ; do
		unset PROPS; typeset -A PROPS
		JSON.getVal $S PROPS
		JSON.getVal ${PROPS['type']} TYPE || continue
		RES[${TYPE%%-*}]="${TYPE}"
		JSON.getVal ${PROPS['token']} S && RES["${TYPE}-token"]="$S"
		# Boulder Section 7.5 - uses uri instead of url
		JSON.getVal ${PROPS['uri']} S && RES["${TYPE}-uri"]="$S"
		# v07
		JSON.getVal ${PROPS['url']} S && RES["${TYPE}-url"]="$S"
		# 7.5.1
		JSON.getVal ${PROPS['status']} S && RES["${TYPE}-status"]="$S"
		JSON.getVal ${PROPS['validated']} S && RES["${TYPE}-validated"]="$S"
		JSON.getVal ${PROPS['keyAuthorization']} S && \
			RES["${TYPE}-keyAuthorization"]="$S"
	done
	return 0
}

# 8.1
Man.addFunc getKeyAuthorization '' '[+NAME?getKeyAuthorization - get the key authorization string for a token.]
[+DESCRIPTION?Generates the key authorization string to use to answer challenges. \avnameCFG\a represents the current configuration used to obtain all data to construct the required JSON Web Key (JWK) and its thumbprint. \avname\a is the name of the variable, where the result gets stored. \atoken\a is the token to use, which is usually obtained from the challenge to answer.]
\n\n\avnameCFG\a \avname\a \atoken\a
'
function getKeyAuthorization {
	typeset -n CFG=$1 S=$2
	typeset T

	S="$3".
	prepareJWS_PH CFG || return 1	# make sure we have the JWK
	JSON.toString ${CFG[PH-JWK]} T || return 2
	shaHash CFG T 256 || return 3
	hexdump2str T || return 4
	str2base64url CFG T 1 || return 5
	S+="$T"
	(( VERB )) && Log.info "key authorization: $S"
	return 0
}

Man.addFunc stopChallengeResponseServer '' '[+NAME?stopChallengeResponseServer - stop the internal ACME challenge response server.]
[+DESCRIPTION?Instruct the internal ACME challenge response server to terminate and closes related pipes.]
\n\n\avnameCFG\a
'
function stopChallengeResponseServer {
	typeset -n CFG=$1
	integer FD=${CFG[SACME-FD]} NFD
	if [[ -e /proc/${CFG[SACME-PID]} ]]; then
		printf '%T\n' >"${CFG[RESPONSE_DIR]}/sacme.exit"
		# make a request, so that the server gets a chance to check for the file
		if redirect {NFD}<>/dev/tcp/localhost/${CFG[PORT]} ; then
			print -u ${NFD} 'EXIT'
			redirect {NFD}>&-
			redirect {NFD}<&-
		fi
	fi
	FD=${CFG[SACME-FD]}
	redirect {FD}>&-
	redirect {FD}<&-
	CFG[SACME-FD]=-1
}

Man.addFunc readRequestLog '' '[+NAME?readRequestLog - read and show the request log of the internal ACME challenge response server.]
[+DESCRIPTION?Read the request log of the internal ACME challenge response server and write it as INFO to stderr. Terminates automatically as soon as the server gets instructed to terminate or is not alive anymore (check period: 1 s).]
\n\n\avnameCFG\a
' 
function readRequestLog {
	typeset -n CFG=$1
	integer FD=${CFG[SACME-FD]} PPID=${CFG[SACME-PID]}
	typeset EXIT="${LE_TMP}/sacme.exit"
	typeset X
	(( FD == -1 )) && return 1
	while [[ ! -e ${EXIT} ]] && [[ -e /proc/${PPID} ]]; do
		while read -t 1 -u ${FD} X ; do
			[[ $X =~ ^127.0.0.1\ (START|EXIT)\  ]] && continue
			Log.info "Acme-Server-Request $X answered."
		done
	done
}

function startChallengeResponseServer {
	typeset -n CFG=$1
	typeset PFEXEC
	integer FD NFD

	cat >${LE_TMP}/acme-server.sh<<EOF
#!/usr/bin/python
#include "includes/AcmeHTTPServer.py"
EOF
	chmod 755 ${LE_TMP}/acme-server.sh
	(( CFG[PORT] < 1024 )) && PFEXEC="${CFG[PFEXEC]}" || PFEXEC=

	rm -f ${LE_TMP}/sacme.out
	mkfifo ${LE_TMP}/sacme.out
	redirect {FD}<>${LE_TMP}/sacme.out
	CFG[SACME-FD]=${FD}

	(( VERB )) && Log.info 'Starting ACME challenge response server on port' \
		"${CFG[PORT]} ..."
	${PFEXEC} ${LE_TMP}/acme-server.sh \
		"${CFG[RESPONSE_DIR]}" "/${CFG[PREFIX]}" ${CFG[PORT]} \
		>${LE_TMP}/sacme.out 2>${LE_TMP}/sacme.err &
	CFG[SACME-PID]=$!
	sleep 1		# give it some time to come up/go down

	# we can't use SIGKILL because it might run under a privileged role/account
	if [[ -e /proc/${CFG[SACME-PID]} ]]; then
		redirect {NFD}<>/dev/tcp/localhost/${CFG[PORT]}
		print -u ${NFD} 'START'
		redirect {NFD}<&-
		redirect {NFD}>&-
		if (( VERB )); then
			readRequestLog CFG &
		fi
		(( VERB )) && Log.info 'Done.'
		return 0
	fi
	T='Failed:'
	while read -t 1 -u ${FD} X 2>/dev/null ; do
		T+="$X\n"
	done
	[[ -s ${LE_TMP}/sacme.err ]] && T+=$(<${LE_TMP}/sacme.err)
	[[ -n $T ]] && Log.warn "$T"
	redirect {FD}>&-
	redirect {FD}<&-
	CFG[SACME-FD]=-1
	return 2
}

# 7.5
Man.addFunc triggerHttpChallenge '' '[+NAME?triggerHttpChallenge - trigger an HTTP challenge response request.]
[+DESCRIPTION?Based on the parsed response (\avnameAUTHZ\a populated by \bgetChallenges()\b) of an authorization request for the related domain, generate the answer to the \bhttp-01\b challenge, and either store it in the apprioriate web server directory (see LE_ENV \bRESPONSE_DIR\b), or - if \bPORT\b is set to != 0 - start a co-process, which answers the related ACME challenge response request while running in the background. The path to the response file gets stored in \avnameCFG\a[RES-FILE]], if available. Finally instructs the ACME server to check the answer immediately, i.e fire the request.]
[+EXIT STATUS?\b1\b on error and it does not make any sense to continue with status auhz requests, \b0\b otherwise.]
[+SEE ALSO?\bserveChallengeResponse()\b.]
\n\n\avnameCFG\a \avnameAUTHZ\a
'
function triggerHttpChallenge {
	typeset -n CFG=$1 AUTHZ=$2
	typeset T V X DOM="${AUTHZ['DOMAIN']}" PH PL URL
	integer L

	[[ -n ${AUTHZ['http-01-status']} ]] && X=${AUTHZ['http-01-status']} ||\
		X=${AUTHZ['STATUS']}
	if [[ $X == 'valid' ]]; then
		Log.info "Authorized for '${DOM}'."
		return 0
	elif [[ $X == 'invalid' ]]; then
		Log.warn "Not authorized for '${DOM}'."
		[[ -n ${AUTHZ['error-detail']} ]] && Log.warn "${AUTHZ['error-detail']}"
		return 3
	elif [[ $X != 'pending' ]]; then
		Log.warn "Invalid server response - authorization failed for '${DOM}'."
		return 4
 	fi
	URL="${AUTHZ['http-01-url']}"
	[[ -z ${URL} ]] && URL="${AUTHZ['http-01-uri']}"	# IS_LE
	if [[ -z ${URL} || -z ${AUTHZ['http-01-token']} ]] ; then
		Log.warn "Invalid server response - authorization failed for '${DOM}'."
		return 5
	fi
	getKeyAuthorization CFG T "${AUTHZ['http-01-token']}" || return 6
	CFG[DOM-RESPONSE]="$T"

	prepareDefaultPH CFG PH "${URL}" || return 10

	# payload
	JSON.newString L 'http-01' && return 12 || V="type $L"
	JSON.newString L "${CFG[DOM-RESPONSE]}" && return 13 || \
		V+=" keyAuthorization $L"
	if (( CFG[IS_LE] )); then
		# https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4.1
		JSON.newString L 'challenge' && return 14 || V+=" resource $L"
	fi
	JSON.newObject L && return 15
	JSON.setVal $L $V || return 16
	T=
	JSON.toString $L PL || return 17
	
	createSig CFG T PL "${PH}" || return 20

	newRequestBody T "${PH}" "${PL}" "$T" || return 30

	# put the response in place [and start the http serv process]
	V="${CFG[RESPONSE_DIR]}/${AUTHZ['http-01-token']}"
	L=0
	if (( CFG[MY_RESPONSE] )); then
		:	# fall through
	elif [[ -d ${CFG[RESPONSE_DIR]} ]]; then
		if print -n -- "${CFG[DOM-RESPONSE]}" >"$V" ; then
			CFG[RES-FILE]="$V"
			(( VERB )) && Log.info "Response file '$V' created."
			L=1
		fi
	fi
	# too lazy to scan stty output for 'intr' setting ;-)
	if (( ! L )); then
		print -n -- "${CFG[DOM-RESPONSE]}" \
			>"${CFG[CFG-DIR]}/${CFG[CA]}/d-${DOM}.res"
		L=$?
		if (( CFG[MY_RESPONSE] )); then
			Log.warn '\nPlease start your challenge response server' \
				"\tfor /${CFG[PREFIX]}/${AUTHZ['http-01-token']}" \
				"\twith  ${CFG[DOM-RESPONSE]}\n" \
				'\t\tand press <ENTER> key to continue or <CTRL><c> to abort.\n'
		elif (( L )); then
			Log.warn "\nPlease create or overwrite the file" \
				"\n${CFG[RESPONSE_DIR]}/${AUTHZ['http-01-token']}" \
				"\n\t\twith the contents" \
				"\n${CFG[DOM-RESPONSE]}\n" \
				'\t\tand press <ENTER> key to continue or <CTRL><c> to abort.\n'
		else
			Log.warn '\nPlease:' \
				"\ncp '${CFG[CFG-DIR]}/${CFG[CA]}/d-${DOM}.res'" \
				"'${CFG[RESPONSE_DIR]}/${AUTHZ['http-01-token']}'\n" \
				'\t\tand press <ENTER> key to continue or <CTRL><c> to abort.\n'
		fi
		yorn y 'Continue?'
	fi

	unset RESULT PARAMS ; typeset -A RESULT PARAMS
	(( VERB )) && \
		Log.info "Trigger challenge response request for '${DOM}':\n\t$T"
	PARAMS=( [URL]="${URL}" [METHOD]='POST' [DATA]="$T" [DUMP]='challenge' )
	fetch CFG RESULT PARAMS
	check403 RESULT

	integer SC=${RESULT[STATUS_CODE]}
	# Boulder Section 7.5
	if (( SC == 202 || SC == 200 )); then
		(( VERB )) && Log.info "'${DOM}' challenge response request triggered."
		# v04 6.5.1: "The server provides a 200 (OK) response with the
		# updated challenge object as its body.", which now includes a
		# in addition a keyAuthorization field.
		getChallenges -s "${RESULT[BODY]}" AUTHZ || return 40
		(( VERB )) && \
			Log.info "'${DOM}' authorization: ${AUTHZ['http-01-status']}"
		# we do not store it, because usually the state is 'pending'
	else
		V="'${DOM}' challenge response request failed"
		[[ ${RESULT[_RES_detail]} ]] && V+=" with '${RESULT[_RES_detail]}'"
		Log.fatal "$V."
		return 50
	fi
	return 0
}

Man.addFunc getCachedDomainStatus '' '[+NAME?getCachedDomainStatus - get the cached authz status for one or more domains.]
[+DESCRIPTION?If \avnameCFG\a[CFG-DIR]]/\avnameCFG\a[CA]/d-\avnameAUTHZ\a[DOMAIN]].status exists (see \bgetChallenges()\b wrt. to contents), it gets parsed in and EXPIRED re-calculated, if the EXPIRES key-value-pair has been found. If there is no such file, \b1\b gets returned. If \avnameAUTHZ\a[DOMAIN]] does not match the DOMAIN value of the file, \b2\b gets returned. Otherwise \avnameAUTHZ\a gets updated with the values obtained from the file and returns \b0\b.]
\n\n\avnameCFG\a \avnameAUTHZ\a
'
function getCachedDomainStatus {
	typeset -n CFG=$1 AUTHZ=$2
	typeset LINE KEY VAL X
	integer NOW
	typeset -A RES
	[[ -r "${CFG[CFG-DIR]}/${CFG[CA]}/d-${AUTHZ[DOMAIN]}".status ]] || return 1

	while read LINE ; do
		[[ ${LINE:0:1} == '#' ]] && continue
		VAL="${LINE#*=}"
		KEY="${.sh.match%=}"
		[[ -z ${KEY} ]] && continue
		if [[ ${KEY} =~ ^(ID_TYPE|STATUS|DOMAIN|EXPIRES)$ ]] || \
				[[ ${KEY} =~ ^(http|dns|tls-alpn)-[0-9]+-(uri|status|token)$ ]]
		then
			if [[ ${VAL:0:1} == "'" ]] ; then
				X=${VAL:1}
				VAL=${X%%\'*}
			fi
			RES[${KEY}]="${VAL}"
		fi
	done<"${CFG[CFG-DIR]}/${CFG[CA]}/d-${AUTHZ[DOMAIN]}".status
	if (( RES[EXPIRES] )); then
		NOW=${ printf '%(%s)T' "now" ; }
		(( NOW < RES[EXPIRES] )) && RES[EXPIRED]=0 || RES[EXPIRED]=1
	fi
	[[ ${AUTHZ[DOMAIN]} == ${RES[DOMAIN]} ]] || return 2 
	mergeB2A AUTHZ RES
	return 0
}

Man.addFunc checkDomainStatus '' '[+NAME?checkDomainStatus - check the authz status for one or more domains.]
[+DESCRIPTION?Check and optionally update the authz status of the given \adomains\a (a space separated list). If \b--force\b is not given, the cached status (if any) will be used unless expired. If no cached status is available (and thus no status URL to query), \ahttp-uri\a would be used as fallback for the status URL to query - this of course makes only sense for a single domain. If no status query URL can be determined, the related domain gets append to \avnameSTATUS\a[unknown]]. Otherwise, depending on the query result, the domain gets append to \avnameSTATUS\a[valid|invalid|pending]].]
[+EXIT STATUS?\b0\b, always.]
[f:force?Update the authz state by quering the related state URL, no matter whether a cached, still fresh status exists. Basically related only to \bvalid\b authz objects, because \binvalid\b authz objects keep their state unless expired or deleted, and \bpending\b authz objects gets queried anyway.]
[i:interval]:[seconds?The number of \aseconds\a to sleep until a status URL gets queried again. Default: 3]
[t:timeout]:[seconds?The status URL gets queried per default every 3s until the returned state is != \bpending\b or the timeout of \aseconds\a gets hit. A value of \b0\b seconds (the default) makes sure that the status URL gets queried only once. Default: \avnameCFG\a[TIMEOUT]].]
[l:local?Do not fetch the status via Internet, but use cached status records, only.]
[u:url]:[http-uri?The status URL to query, if there is no cached status record (and thus no status URL). This makes of course only sense for a single domain.]
\n\n\avnameCFG\a \avnameSTATUS\a \adomains\a
'
function checkDomainStatus {
	typeset DOMS X URL STATUS F
	integer TIMEOUT=0 FORCE=0 INTERVAL=3 OK=0 LOCAL=0 SMASK=0 COUNT
	typeset -A AUTHZ RESULT PARAMS=( [URL]= [METHOD]='GET' [DUMP]='status' )

	X="${ Man.funcUsage $0 ; }"
	while getopts "${X}" option ; do
		case "${option}" in
			f) FORCE=1 ;;
			i) INTERVAL=${OPTARG} ;;
			l) LOCAL=1 ;;
			t) TIMEOUT=${OPTARG} ; (( SMASK |= 15 )) ;;
			u) URL=${OPTARG} ;;
		esac
	done
	OK=$((OPTIND-1))
	shift ${OK}
	OPTIND=1

	typeset -n CFG=$1 STATUS_MAP=$2
	DOMS="$3"
	(( INTERVAL < 1 )) && INTERVAL=3
	(( SMASK & 15 )) || TIMEOUT=${CFG[TIMEOUT]}

	[[ -z ${DOMS} ]] && return 0
	COUNT=0
	for X in ${DOMS} ; do
		unset AUTHZ ; typeset -A AUTHZ=( [DOMAIN]="$X" )
		getCachedDomainStatus CFG AUTHZ
		[[ -n ${AUTHZ[STATUS]} ]] && STATUS=${AUTHZ[STATUS]} || \
			STATUS=${AUTHZ['http-01-status']}
		# LE does not handle invalid authz as defined. So prefer to make some
		# more request than needed instead of getting busted ...
		if [[ ${STATUS} =~ ^(in)?valid$ ]] && (( ! FORCE )); then
			(( AUTHZ[EXPIRES] && ! AUTHZ[EXPIRED] )) && \
				STATUS_MAP[${STATUS}]+=" $X" && continue
		fi

		# determine the authz URL
		V=
		[[ -f "${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".url ]] && \
			V=$(<"${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".url)
		if [[ -z $V ]]; then
			# fallback: works at least for LE -> deduce from challenge URL
			# and all the trouble because they are not able to separate app
			# and transport protocol data properly ... - grrr
			V="${AUTHZ['http-01-url']}"
			[[ -z $V ]] && V="${AUTHZ['http-01-uri']}"	# IS_LE
			F="${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".challenges
			if [[ -z $V && -e $F ]]; then
				getChallenges -f "$F".challenges AUTHZ
				V="${AUTHZ['http-01-url']}"
				[[ -z $V ]] && V="${AUTHZ['http-01-uri']}"	# IS_LE
			fi
			if [[ -n $V ]]; then
				V="${V//challenge/authz}"
				V="${V%/*}"
			elif [[ -n ${URL} ]]; then
				V="${URL}"
				AUTHZ[EXPIRED]=1
			fi
		fi
		# no query URL => suspect
		[[ -z $V ]] && STATUS_MAP[unknown]+=" $X" && continue

		(( LOCAL )) && STATUS_MAP[pending]+=" $X" && continue

		# need to fetch pending or expired authz objects
		PARAMS[URL]="$V"
		SECONDS=0
		OK=0
		while (( SECONDS < TIMEOUT )); do
			sleep ${INTERVAL}
			(( COUNT++ ))
			fetch CFG RESULT PARAMS
			check403 RESULT
			integer SC=${RESULT[STATUS_CODE]}
			if (( SC == 200 || SC == 202 )); then
				if getChallenges -s "${RESULT[BODY]}" AUTHZ; then
					STATUS=${AUTHZ[STATUS]}
					if [[ ${STATUS} == 'invalid' ]]; then
						STATUS_MAP[invalid]+=" $X"
						[[ -n ${AUTHZ['error-detail']} ]] && \
							Log.warn "Domain '$X' status is invalid:" \
								"${AUTHZ['error-detail']}."
						OK=1
						break
					elif [[ ${STATUS} == 'valid' ]]; then
						STATUS_MAP[valid]+=" $X"
						(( VERB )) && Log.info "Domain '$X' status is valid."
						OK=1
						break
					elif (( COUNT == 3 )); then
						Log.info "Still waiting for '$X' authorization result."\
							"Current status: ${STATUS}."
						COUNT=0
					fi
				elif (( VERB )); then
					Log.info "Domain status answer not JSON conform:\n"
					print -u2 -r "${RESULT[BODY]}"
				fi
			elif (( VERB )); then
				Log.info "HTTP-Status: ${SC}. Ignored answer: \n${RESULT[BODY]}"
			fi
		done
		if (( OK )); then
			[[ -n ${CFG[RES-FILE]} ]] && \
				rm -f "${CFG[RES-FILE]}" && CFG[RES-FILE]=
			AUTHZ[EXPIRED]=0
		else
			STATUS_MAP[pending]+=" $X"
		fi
		dumpArray AUTHZ >"${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".status
	done
	return 0
}

# 7.4.1
Man.addFunc authDomain '' '[+NAME?authDomain - handle domain authorizations.]
[+DESCRIPTION?Handles the authorization for \avnameCFG\a\b[DOMAINS]]\b, which is expected to contain a comma separated list of the domains in question. It applies a simple "syntax" check on each domain and returns \b1\b if an invalid domain has been found or if there are no domains to check. The final list of uniqe domains to check gets stored as \avnameCFG\a[AUTZ-DOMAINS]] keeping the same order as in \avnameCFG\a\b[DOMAINS]]\b]. Finally the authzorization status for each domain gets checked, and if it is not \bvalid\b, a corresponding authorization object gets created and validated by triggering and answering related ACME HTTP challenges. Wenn all checked domains are valid, this function returns \b0\b, if an error occures a value < 100, the number of invalid/pending domains + 100 otherwise.]
\n\n\avnameCFG\a
'
function authDomain {
	typeset -n CFG=$1
	typeset DOMS= CDUMP URL PH PL T V X A
	integer L=0 JDNS JID JVAL JPL ERR=0 TODO=0
	typeset -A PARAMS STATUS

	# check domains - fail early
	X="${CFG[DOMAINS]}"
	for X in ${X//,/ } ; do
		[[ -z $X ]] && continue
		if checkDomainSyntax "$X" ; then
			[[ -z ${STATUS["$X"]} ]] && DOMS+=" $X" && STATUS["$X"]=1
		else
			(( L++ ))
		fi
	done
	(( L )) && return 1
	[[ -z ${DOMS} ]] && Log.info 'No domain for authorization specified' \
		'- nothing to do.' && return 1
	CFG[AUTHZ-DOMAINS]="${DOMS}"
	unset STATUS; typeset -A STATUS

	getNonce CFG || return 2
	typeset -n DIRKEY=${CFG[DIR-KEY]}

	URL=${CFG[URL-authz]}
	[[ -z ${URL} ]] && Log.fatal 'Unknown new-authz URL.' && return 3

	# recylce bin
	JSON.newObject JPL && return 8
	if (( CFG[IS_LE] )); then
		# draft-ietf-acme-acme-02#section-6.4
		JSON.newString JDNS 'dns' && return 4
		JSON.newString JVAL 'unset' && return 5	# placeholder
		JSON.newObject JID && return 6
		JSON.setVal ${JID} 'type' ${JDNS} 'value' ${JVAL} || return 7
		V="identifier ${JID}"
		JSON.newString L "${DIRKEY[authz]}" && return 9 || V+=" resource $L"
		JSON.setVal ${JPL} $V || return 9
	fi

	if (( CFG[FORCE_AUTH] )); then
		TODO=1
	else
		(( CFG[FORCE_STATUS] )) && V='-f' || V=
		checkDomainStatus $V CFG STATUS "${DOMS}"
		DOMS=
		[[ -n ${STATUS[pending]} ]] && A=( ${STATUS[pending]} ) && \
			(( TODO+=${#A[@]} )) && DOMS=" ${STATUS[pending]}"
		[[ -n ${STATUS[unknown]} ]] && A=( ${STATUS[unknown]} ) && \
			(( TODO+=${#A[@]} )) && DOMS+=" ${STATUS[unknown]}"
		# actually the RFC says, that this state should be kept until it is
		# expired or the domain gets explicitly released. LE does not work this
		# way: It allows to release only 'pending' and 'valid' domains. Thus
		# one would not be able to 'recover' a domain, if e.g. first try of
		# answering a challenge was not successful. So ignore the RFC and
		# simply re-auth - since LE does not cache, it simply creates a new
		# authz object.
		[[ -n ${STATUS[invalid]} ]] && A=( ${STATUS[invalid]} ) && \
			(( TODO+=${#A[@]} )) && DOMS+=" ${STATUS[invalid]}"
	fi

	if (( TODO && CFG[PORT] && ! CFG[MY_RESPONSE] )); then
		CFG[RESPONSE_DIR]="${LE_TMP}/res"
		if [[ ! -d ${CFG[RESPONSE_DIR]} ]]; then
			mkdir -p "${CFG[RESPONSE_DIR]}" || return 12
		fi
		startChallengeResponseServer CFG || return 12
	fi

	# payload
	PARAMS=( [URL]="${URL}" [METHOD]='POST' [DATA]= [DUMP]= )
	CFG[DOM-TBD]=
	for X in ${DOMS} ; do
		Log.info "Getting new authorization data for '$X' ..."
		CDUMP="${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".challenges

		prepareDefaultPH CFG PH "${URL}" || return 11

		# payload
		PL=
		JSON.setVal ${JVAL} "$X" || return 12
		JSON.toString ${JPL} PL || return 13

		createSig CFG T PL "${PH}" || return 20

		newRequestBody T "${PH}" "${PL}" "$T" || return 30
		(( VERB )) && Log.info "Sending authz request\n\t$T"

		unset RESULT AUTHZ; typeset -A RESULT AUTHZ
		PARAMS[METHOD]='POST' PARAMS[DATA]="$T" PARAMS[DUMP]=
		fetch CFG RESULT PARAMS
		check403 RESULT

		V=
		integer SC=${RESULT[STATUS_CODE]}
		# What an aweful brain damaged idea to store app. data in the
		# response header!
		if [[ -n ${RESULT[Location]} ]]; then
			V="${RESULT[Location]}"
			print "$V" >"${CDUMP%.*}".url
		fi
		if (( SC == 201 )); then
			# authorization object created
			print -rn -- "${RESULT[BODY]}" >"${CDUMP}"
			if getChallenges -s "${RESULT[BODY]}" AUTHZ ; then
				dumpArray AUTHZ >"${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".status
				(( AUTHZ[EXPIRED] )) && L=0
			fi
		else
			L=0
			(( ERR++ ))
			V="Authorization request submission for '$X' failed"
			[[ ${RESULT[_RES_detail]} ]] && \
				V+=" with '${RESULT[_RES_detail]}'."
			Log.warn "${V}."
		fi
		if (( L )) && triggerHttpChallenge CFG AUTHZ ; then
			if [[ ${AUTHZ[STATUS]} == 'valid' ]]; then
				# usually not
				dumpArray AUTHZ >"${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".status
				continue
			fi
			unset RESULT; typeset -A RESULT
			checkDomainStatus -f CFG RESULT "$X"
			[[ -n ${RESULT[valid]} ]] && continue
		fi
		(( ERR++ ))
		CFG[DOM-TBD]+=" $X"
	done
	if (( TODO && CFG[PORT] && ! CFG[MY_RESPONSE] )); then
		stopChallengeResponseServer CFG		# make sure the port gets released
	fi

	if [[ -n ${CFG[DOM-TBD]} ]]; then
		Log.warn "The following domains are not yet authorized:${CFG[DOM-TBD]}"
	else
		Log.info 'All given domains are valid.'
	fi
	(( ERR )) && (( ERR+=100 ))
	return ${ERR}
}

Man.addFunc listDomains '' '[+NAME?listDomains - list all domains once touched wrt. the current CA in use.]
[+DESCRIPTION?Print out the domains ever touched wrt. to authorizations from the CA currently used. It just scans the current config directory for *.status and *.challenges files and strips off the prefix and suffix.]
\n\n\avnameCFG\a
'
function listDomains {
	typeset -n CFG=$1
	typeset X F
	typeset -A D

	[[ -d ${CFG[CFG-DIR]}/${CFG[CA]} ]] || return 0
	cd ${CFG[CFG-DIR]}/${CFG[CA]}
	for F in ~(N)d-*.challenges ; do
		[[ -n $F ]] && D["${F:2:${#F}-13}"]=1
	done
	for F in ~(N)d-*.status ; do
		[[ -n $F ]] && D["${F:2:${#F}-9}"]=1
	done
	X="${!D[@]}"
	[[ -z $X ]] && return 0
	set -s -- $X
	print 'Domains: ' "$@"
}

Man.addFunc createCSR '' '[+NAME?createCSR - create a Certificate Signing Request (CSR).]
[+DESCRIPTION?Create a Certificate Signing Request (CSR) for all the domains given by \avnameDOMS\a (indexed array) using the configuration provided by \avnameCFG\a. On success the generated CSR PEM file gets stored into \aKEYFILE\a but the extension \bkey\b replaced by \bcsr\b.]
\n\n\avnameCFG\a \avnameDOMS\a \aKEYFILE\a
'
function createCSR {
	typeset -n CFG=$1 DOMS=$2
	typeset T= X  KEYFILE="$3" CSRCFG="${LE_TMP}/csr.cfg" BN="${KEYFILE%.*}"
	integer I=0

	for X in ${DOMS[@]} ; do
		T+="DNS.${I}=$X\n"
		(( I++ ))
	done
	if [[ -f ${BN}.cfg ]]; then
		${CFG[SED]} -e '/^subjectAltName/ d' \
			-e '/^req_extensions/ d' \
			-e '/^distinguished_name/ d' \
			-e "/^CN/ d" \
			-e '/^DNS./ d' \
			 ${BN}.cfg | \
		${CFG[SED]} -re "/^\[ *alt_subjects *\]/ a\\$T" \
			-e '/^\[ *req *\]/ a\req_extensions = v3_req\ndistinguished_name = req_DN' \
			-e "/^\[ *req_DN *\]/ a\CN = ${DOMS}\nCN_default = ${DOMS}" \
			-e '/^\[ *v3_req *\]/ a\subjectAltName = @alt_subjects' \
			>${CSRCFG}
		egrep -q '^\[ *v3_req *\]' || \
			print "[v3_req]\nsubjectAltName = @alt_subjects\n" >>${CSRCFG}
		egrep -q '^\[ *alt_subjects *\]' || \
			print "[alt_subjects]\n$T" >>${CSRCFG}
	else
		T=${ print -n -- "$T"; }
		cat >${CSRCFG}<<EOF
[ req ]
default_md			= sha256
utf8				= yes
string_mask			= utf8only
distinguished_name	= req_DN
attributes			= req_attrs
req_extensions		= v3_req

[ req_attrs ]

[ req_DN ]
CN_max              = 64
CN                  = ${DOMS}
CN_default			= ${DOMS}

[ v3_req ]
subjectAltName		= @alt_subjects

[ alt_subjects ]
$T
EOF
	fi

	cp ${CSRCFG} "${BN}.txt"
	(( VERB )) && Log.info "Created '${BN}.txt'."

	${CFG[OPENSSL]} req -new -outform PEM -out "${BN}.csr" -subj "/CN=${DOMS}" \
		-key "${KEYFILE}" -config "${CSRCFG}" >/dev/null || return 2
	Log.info "Created '${BN}.csr'."
	return 0
}

Man.addFunc saveCert '' '[+NAME?saveCert - convert and save a certifificate.]
[+DESCRIPTION?Tries to convert the certificate in \avnameRES\a[FILE]] from DER to PEM and store it as \aDST\a. On success \b0\b gets returned. If a conversation error occures, the file gets stored as is in \aDST\a\b.tmp\b and return code set to \b3\b. If the file is empty and there is a \bLocation\b entry in \avnameRES\a then \b1\b gets returned silently, otherwise \b2\b.]
\n\n\avnameCFG\a \avnameRES\a \aDST\a
'
function saveCert {
	typeset -n CFG=$1 RES=$2
	typeset DST="$3" F X
	if [[ ! -s ${RES[FILE]} ]]; then
		[[ -n ${RES[Location]} ]] && return 1	# retry
		Log.fatal 'The server did not send a certificate and no Location'
			'header. This is not RFC conform and should be reported to'
			'the ACME server support team.'
		return 2
	fi

	${CFG[OPENSSL]} x509 -inform DER -in "${RES[FILE]}" -out "${DST}"
	if (( ! $? )); then
		Log.info "Certificate stored as '${DST}'"
		if [[ -n ${CFG[CERT_DIR]} ]]; then
			if [[ -d ${CFG[CERT_DIR]} ]]; then
				F="${DST##*/}"
				F="${F:2}"
				[[ -n ${CFG[CERT_EXT]} ]] && F="${F%.*}.${CFG[CERT_EXT]}"
				X=${ cp "${DST}" "${CFG[CERT_DIR]}/$F" 2>&1 ; }
				[[ -n $X ]] && Log.warn 'Failed to copy certificate to' \
					"'${CFG[CERT_DIR]}/$F': $X"
			else
				Log.warn "Directory '${CFG[CERT_DIR]}' does not exist." \
					'Unable to copy certificate file to this location, too.'
			fi
		fi
		return 0
	fi
	cp "${RES[FILE]}" "${DST}.tmp"
	Log.fatal 'Unable convert the issued certificate.' \
		"The garbage has been saved to '${DST}.tmp'." \
		'Please check the contents and add an issue on' \
		'https://github.com/jelmd/acme-ksh/.'
	return 3
}

Man.addFunc listCerts '' '[+NAME?listCerts - list all certificates obtained from the current CA in use.]
[+DESCRIPTION?Print out the common names of all certificates of the CA currently used. It just scans the current config directory for *.crt files and strips off the prefix and suffix.]
\n\n\avnameCFG\a
'
function listCerts {
	typeset -n CFG=$1
	[[ -n $2 ]] && typeset -n L=$2 || integer I=1
	typeset X F
	typeset -A D

	[[ -d ${CFG[CFG-DIR]}/${CFG[CA]} ]] || return 0
	cd ${CFG[CFG-DIR]}/${CFG[CA]}
	X=
	for F in ~(N)r-*.crt ; do
		[[ -n $F ]] && X+=" ${F:2:${#F}-6}"
	done
	[[ -z $X ]] && return 0
	set -s -- $X
	L="$@"
	(( I )) && print 'Common names/Certificates: ' "$@"
}

Man.addFunc certSummary '' '[+NAME?certSummary - show a summary for each certificate found.]
[+DESCRIPTION?Show a summary for each certificate found wrt. to the CA currently used, i.e. all certificates which would be shown by \blistCerts()\b.]
\n\n\avnameCFG\a
'
function certSummary {
	typeset -n CFG=$1
	typeset CERTS DOMS LINE F V X CN
	listCerts CFG CERTS
	[[ -z ${CERTS} ]] && return 0

	integer I=0 AFTER BEFORE NOW=${ printf '%(%s)T' now ; }
	cd ${CFG[CFG-DIR]}/${CFG[CA]}
	for F in ${CERTS} ; do
		I=0 AFTER=0 BEFORE=0 DOMS=",$F" CN="$F"
		${CFG[OPENSSL]} x509 -in r-"$F".crt -text -noout 2>/dev/null | \
		while read LINE; do
			(( I++ ))
			if [[ ${LINE:0:11} == 'Not After :' ]]; then
				AFTER=${ printf '%(%s)T' "${LINE:12}" ; }
			elif [[ ${LINE:0:11} == 'Not Before:' ]]; then
				BEFORE=${ printf '%(%s)T' "${LINE:12}" ; }
			elif [[ ${LINE:0:32} == 'X509v3 Subject Alternative Name:' ]]; then
				read LINE
				for X in ${LINE} ; do
					[[ ${X:0:4} == 'DNS:' ]] || continue
					V="${X:4}"
					X="${V%,}"
					[[ $X == ${CN} ]] && continue
					DOMS+=",$X"
				done
				break	# now we should have all we need
			fi
		done
		(( I )) || continue
		if (( NOW < BEFORE )); then
			V='N'
		else
			(( AFTER < NOW  )) && V='X' || V='V'
		fi
		X=${ printf '%(%F %T)T' "10#${BEFORE}" ; }
		F=${ printf '%(%F %T)T' "10#${AFTER}"  ; }
		print "$V\t$X .. $F\t${DOMS:1}"
	done
}

Man.addFunc getCert '' '[+NAME?csr - create and submit a CSR.]
[+DESCRIPTION?Create and submit a Certificate Signing Request (CSR) for all the domains given by \avnameCFG\a[AUTHZ-DOMAINS]. \bauthDomain()\b should have been used to create and validate each item in this space separated list of uniqe domains. The first domain in this list will be used as the common name (CN) of the CSR and thus of the possible issued certificate. If the \avnameCFG\a[CFG-DIR]/\avnameCFG\a[CA]/r-\aCN\a.key exists, it will be used to read the private rsa key from it. If it is secured by a passphrase, openssl will ask for it - therefore in this case the script will not work in non-interactive aka batch mode. If the file does not yet exists, a new key pair gets created using \bopenssl genrsa\b \a...\a and stored into this file without securing it with a passphrase. If \avnameCFG\a[CFG-DIR]/\avnameCFG\a[CA]/r-\aCN\a.cfg exists, it will be used as the config to create the CSR. Otherwise a generic internal config will be used, which is sufficient for LE.]
\n\n\avnameCFG\a
'
function getCert {
	typeset -n CFG=$1
	typeset -n DIRKEY=${CFG[DIR-KEY]}
	[[ -z ${CFG[AUTHZ-DOMAINS]} ]] && Log.warn 'No authzorized domains.' \
		'Nothing to do.' && return 1

	typeset T V X PH PL KFILE URL="${CFG[URL-order]}"
	typeset -a DOMS=( ${CFG[AUTHZ-DOMAINS]} )
	integer L

	CFG[DOMAIN_ASCII]="${DOMS}"
	getPrivateKey CFG '-TMP' || return 2
	KFILE="${CFG[KEY-FILE-TMP]}"
	createCSR CFG DOMS "${KFILE}" || return 3
	${CFG[OPENSSL]} req -outform der -in ${KFILE%key}csr -out ${LE_TMP}/csr.der

	prepareDefaultPH CFG PH "${URL}" || return 10

	# payload
	file2base64url CFG T ${LE_TMP}/csr.der || return 20
	JSON.newString L "$T" && return 21 || V=" csr $L"
	if [[ -n ${CFG['NOT_BEFORE']} ]]; then
		T=${ TZ=GMT printf '%(%FT%TZ)T' "${CFG['NOT_BEFORE']}" ; }
		JSON.newString L "$T" && return 22 || V+=" notBefore $L"
	fi
	if [[ -n ${CFG['NOT_AFTER']} ]]; then
		T=${ TZ=GMT printf '%(%FT%TZ)T' "${CFG['NOT_AFTER']}" ; }
		JSON.newString L "$T" && return 23 || V+=" notAfter $L"
	fi
	if (( CFG[IS_LE] )); then
		JSON.newString L "${DIRKEY[order]}" && return 24 || V+=" resource $L"
	fi
	JSON.newObject L && return 25
	JSON.setVal $L $V || return 26
	JSON.toString $L PL || return 27

	createSig CFG T PL "${PH}" || return 30

	newRequestBody T "${PH}" "${PL}" "$T" || return 40

	typeset -A PARAMS=( [URL]="${URL}" [METHOD]='POST' [DATA]="$T" [DUMP]= ) RES
	fetch CFG RES PARAMS
	check403 RES

	V=
	integer SC=${RES[STATUS_CODE]}
	if (( SC == 201 )); then
		# LE sends a DER encoded cert as body
		saveCert CFG RES "${KFILE%key}crt" && return 0
		(( $? == 1 )) || return 50

		# go into loop
		PARAMS[URL]="${RES[Location]}" PARAMS[METHOD]='GET' PARAMS[DATA]=
		PARAMS[DUMP]="${CFG[URL-order]##*/}.retry"
		SECONDS=0		# waiting more than 10 minutes is inaccaptable/a DoS
		while (( SECONDS < 600 )); do
			fetch CFG RES PARAMS
			check403 RES
			SC=${RES[STATUS_CODE]}
			if (( SC == 202 )); then
				[[ -n ${RES[Retry-After]} ]] && T=${RES[Retry-After]} || T=10
			elif (( SC == 200 )); then
				saveCert CFG RES "${KFILE%key}crt" && return 0
				(( $? == 1 )) || return 50
				# should be unreachable, but buggy implementations ...
				T=3
			else
				# ignore any errors and try again
				T=3
			fi
			Log.info "Retrying after $T seconds ..."
			sleep $T
		done
		Log.warn 'Unable to get the certificate. The server has probably some' \
			'some problems. Trying again later might be an option.'
		return 51
	else
		V="CSR submission for '${DOMS}' failed"
		[[ ${RES[_RES_detail]} ]] && V+=" with '${RES[_RES_detail]}'."
		Log.warn "${V}."
	fi
}

Man.addFunc checkCert '' '[+NAME?checkCert - expiration check and domain extraction.]
[+DESCRIPTION?Check, whether the certificate stored in the \acert\a file expires before the given  point in time \aex_time\a (seconds since the Epoche, i.e. 00:00:00 UTC, January  1, 1970). If so, set \avnameDOMS\a to a space separated list of unique DNS domains found via \bSubject CN\b and \bX509v3 Subject Alternative Name\b entries of the certificate. The first domain in this list should be used as \bCN\b. If the \bCN\b cannot be determined from the subject of the certificate, it is tried to deduce it from the \acert\a filename - the user will be asked, whether this is correct. If there is no such \acert\a file or it cannot be parsed, the function returns a value > 0, 0 otherwise. If \aex_time\a has a negative value, all certificates get picked up, which expire after |\aex_time\a|.]
\n\n\avnameCFG\a \avnameDOMS\a \acert\a \aex_time\a
'
function checkCert {
	[[ -n $3 && -f $3 ]] || return 1

	typeset -n CFG=$1 RES=$2
	typeset F="$3" X V CN DOMS LINE
	integer TLIMIT=$4 T I=0
	typeset -A DMAP

	(( VERB )) && \
		Log.info "Checking '$F' wrt. ${ printf '%T' 10#${TLIMIT}; } ..."
	RES=
	${CFG[OPENSSL]} x509 -in "$F" -text -noout 2>/dev/null| while read LINE; do
		(( I++ ))
		if [[ ${LINE:0:11} == 'Not After :' ]]; then
			T=${ printf '%(%s)T' "${LINE:12}" ; }
			(( TLIMIT < 0 )) && (( T=-T ))
			if (( TLIMIT < T )); then
				(( VERB )) && \
					Log.info "'$F' is OK (expires" ${ printf '%T)' "10#$T"; }
				return 0
			fi
			(( VERB )) && Log.info "'$F' expires " ${ printf '%T' "10#$T"; }
		elif [[ ${LINE:0:8} == 'Subject:' ]] ; then
			for X in ${LINE} ; do
				[[ ${X:0:3} == 'CN=' ]] || continue
				V="${X:3}"
				X="${V%,}"
				# we try to support "foreign" certs as well, so strip off crap
				V="${X%%/*}"
				checkDomainSyntax "$V" && CN="$V" && DMAP["$V"]=1
				break
			done
		elif [[ ${LINE:0:32} == 'X509v3 Subject Alternative Name:' ]]; then
			read LINE
			for X in ${LINE} ; do
				[[ ${X:0:4} == 'DNS:' ]] || continue
				V="${X:4}"
				X="${V%,}"
				checkDomainSyntax "$X" && (( ! DMAP["$X"] )) && DOMS+=" $X"
			done
			break		# entry order is stable, so no more stuff we need
		fi
	done
	if (( ! I )); then
		Log.warn "'$F' seems not to be a PEM encoded certificate."
		return 2
	fi
	DOMS+=' '
	if [[ -z ${CN} ]] && (( TLIMIT > 0 )) ; then
		X="${F##*/}"
		V="${X#r-}"
		X="${V%.*}"
		checkDomainSyntax "$X" && yorn y "Use CN='$X' for '$F'" && CN="$X"
	fi
	[[ -n ${CN} ]] && DOMS="${CN} ${DOMS// ${CN} / }"
	RES="${DOMS}"
	return 0
}

Man.addFunc findCerts '' '[+NAME?findCerts - find certificate files by domain.]
[+DESCRIPTION?Find certificate files related to the given \adomains\a (a comma or space separated list) and store them with their absolute path as key in the associative array \avnameFOUND\a. If \adomains\a contains the word \ball\b (case in-sensitive), all \b*.crt\b files in the current configuration directory get picked up. If a domain name equals to a filename in the configuration directory or any other existing file, those are incldued as well. If there is no such file, the domain gets prefixed with \br-\b and suffixed with \b.crt\b and included if the corresponding file exists.]
\n\n\avnameCFG\a \avnameFOUND\a \adomains\a
'
function findCerts {
	typeset -n CFG=$1 TBD="$2"
	typeset DOMS="$3" X F OCWD
	typeset -l LOWER

	OCWD="${PWD}"
	for X in ${DOMS//,/ } ; do
		[[ -z $X ]] && continue
		LOWER="$X"
		if [[ ${LOWER} == 'all' || ${LOWER} == '*' ]]; then
			cd "${CFG[CFG-DIR]}/${CFG[CA]}" || continue
			for F in ~(N)*.crt ; do
				[[ -z $F ]] && continue
				TBD["${PWD}/$F"]=1
			done
			cd "${OCWD}"
		elif [[ -f ${CFG[CFG-DIR]}/${CFG[CA]}/$X ]]; then
			cd "${CFG[CFG-DIR]}/${CFG[CA]}" && \
				TBD["${PWD}/${X##*/}"]=1 && cd "${OCWD}"
		elif [[ -f ${CFG[CFG-DIR]}/${CFG[CA]}/r-${X}.crt ]]; then
			cd "${CFG[CFG-DIR]}/${CFG[CA]}" && \
				TBD["${PWD}/r-${X}.crt"]=1 && cd "${OCWD}"
		elif [[ -f $X ]]; then
			[[ $X =~ / ]] && cd "${X%/*}"
			TBD["${PWD}/${X##*/}"]=1
			cd "${OCWD}"
		elif [[ -f r-${X}.crt ]]; then
			TBD["${PWD}/r-${X}.crt"]=1
		else
			Log.warn "Certificate file for '$X' not found - skipping."
		fi
	done
}

Man.addFunc renewCerts '' '[+NAME?renewCerts - renew certificates.]
[+DESCRIPTION?Checks, checks certificates deduced from the space separated list of domain names and PEM cert files passed via \avnameCFG\a[DOMAINS]] for expiration, and renews each which expires in less than \avnameCFG\a[DAYS]]. On success \avnameCFG\a[AUTHZ-DOMAINS]] contains a space separated list of all domains, which got checked wrt. authorization. If the PEM formatted cert file for a given domain cannot be found, it gets ignored, i.e. do not cause the function to exit.]
[+EXIT STATUS?The number of new certificates obtained.]
\n\n\avnameCFG\a
'
function renewCerts {
	typeset -n CFG=$1

	# check domains - fail early
	typeset X
	typeset -A CERTS DOMS TBD
	integer LIMIT I

	(( ${CFG[DAYS]} < 0 )) && \
		LIMIT=${ printf '%(%s)T' "exactly ${CFG[DAYS]##-} days ago" ; } || \
		LIMIT=${ printf '%(%s)T' "exactly in ${CFG[DAYS]} days" ; }

	findCerts CFG TBD "${CFG[DOMAINS]}"

	for X in "${!TBD[@]}" ; do
		if checkCert CFG T "$X" ${LIMIT} ; then
			I=0
			for V in $T ; do
				(( I == 0 )) && CERTS["$V"]="$T" && (( I++ ))
				DOMS["$V"]=1
			done
		fi
	done
	if (( ${#CERTS[@]} == 0 )); then
		 Log.info 'All scanned certificates are fresh enough.' \
			'No need to renew any.'
		return 0
	fi
	CFG[DOMAINS]="${!DOMS[@]}"
	authDomain CFG	# go as far as we can
	I=0
	for X in ${!CERTS[@]} ; do
		CFG[AUTHZ-DOMAINS]="${CERTS["$X"]}"
		getCert CFG && (( I++ ))
	done
	if (( I )); then
		(( I > 1 )) && X='s' || X=
		Log.info "Got $I new certificate${X}."
	else
		Log.info 'No new certificates.'
	fi
	return $I
}

Man.addFunc checkDate '' '[+NAME?checkDate - parse input date and show loacal representation and seconds since epoch.]
[+DESCRIPTION?Parse the given \adate\a according to ksh93 rules (similar to GNU date) and print seconds since epoch (1970-01-01 00:00:00 UTC) as well as local representation to stderr. On error it says \bInvalid date \b\a...\a]
\n\n\adate\a
'
function checkDate {
	integer T=${ printf '%(%s)T' "$1" ; }
	(( $? )) && Log.fatal "Invalid date '$1'." && return 1
	Log.info "'$1' gets interpreted as ${T} seconds since" \
		"'1970-01-01 00:00:00 UTC', i.e. as '${ printf '%T' "10#$T" ; }'."
	return 0
}

# 7.5.2.
Man.addFunc unauthDomain '' '[+NAME?unauthorizeDomain - deactivate authorization for one or more domains.]
[+DESCRIPTION?Release authorizations passed via  \avnameCFG\a[DOMAIN] (a space separated list of domains).]
[+EXIT STATUS?The number of released domains.]
\n\n\avnameCFG\a
'
function unauthDomain {
	typeset -n CFG=$1
	typeset V T X PH PL
	integer L COUNT=0

	[[ -z ${CFG[DOMAINS]} ]] && Log.warn 'No domain specified via option' \
		"'-d ...' - nothing to do." && return 0

	getDirectory CFG
	typeset -n DIRKEY=${CFG[DIR-KEY]}

	# payload
	PL=
	JSON.newString L 'deactivated' && return 2
	V+=" status $L"
	if (( CFG[IS_LE] )); then
		JSON.newString L 'authz' && return 3 || V+=" resource $L"
	fi
	JSON.newObject L && return 3
	JSON.setVal $L $V || return 4
	JSON.toString $L PL || return 5

	typeset -A PARAMS=( [METHOD]='POST' [URL]= [DATA]= [DUMP]='release' )
	for X in ${CFG[DOMAINS]//,/ } ; do
		unset AUTHZ STATUS; typeset -A STATUS AUTHZ=( [DOMAIN]="$X" )
		if [[ -s ${CFG[CFG-DIR]}/${CFG[CA]}/d-${X}.url ]]; then
			URL=$(<${CFG[CFG-DIR]}/${CFG[CA]}/d-${X}.url)
		else
			checkDomainStatus -u "${CFG[URL-authz]}" CFG STATUS "$X"
			# at least for LE this is a workaround
			if ! getCachedDomainStatus CFG AUTHZ ; then
				Log.fatal "Unable to determine the status of domain '$X'." \
					"You probably need to '${PROG} -c authorize -d $X ...'" \
					'to get its current authorization status.'
				continue
			fi
			if [[ -z ${AUTHZ['http-01-uri']} ]]; then
				Log.fatal "Unable to determine the status URL of domain '$X'."\
					"You probably need to '${PROG} -c authorize -d $X ...'" \
					'to get it.'
				continue
			fi
			V="${AUTHZ['http-01-uri']//challenge/authz}"
			URL="${V%/*}"
		fi

		prepareDefaultPH CFG PH "${URL}"

		createSig CFG T PL "${PH}" || return 20

		newRequestBody T "${PH}" "${PL}" "$T" || return 30
		(( VERB )) && Log.info "Sending domain release request\n\t$T"

		unset RESULT AUTHZ; typeset -A RESULT AUTHZ
		PARAMS[URL]="${URL}" PARAMS[DATA]="$T"
		fetch CFG RESULT PARAMS
		check403 RESULT

		integer SC=${RESULT[STATUS_CODE]}
		if (( SC == 200 )); then
			(( VERB )) && Log.info "'$X' released."
			rm -f "${CFG[CFG-DIR]}/${CFG[CA]}/d-$X".*
			(( COUNT++ ))
		else
			V="Releasing domain '$X' failed"
			[[ ${RESULT[_RES_detail]} ]] && V+=" with '${RESULT[_RES_detail]}'"
			Log.fatal "$V."
		fi
	done
	return ${COUNT}
}

Man.addFunc prepareCertPH '' '[+NAME?prepareCertPH - prepare the protected header for a new ACME request using the private key of a certificate.]
[+DESCRIPTION?Basically a wrapper around \bprepareJWS_PH\b \avnameCFG\a \aSUFFIX\a, which uses the key pair of the certificate for \adomain\a to prepare the JWK variant of the protected header for a new ACME request as e.g. needed for certificate revocation. Note that as side effect \avnameCFG\a[DOMAIN_ASCII]] gets set to \adomain\a and \avnamePH\a to the base64url encoded header. \aURL\a is used to set the url value of the protected header.]
[+EXIT STATUS?]{
	[+0?On success.]
	[+1?If the key pair for the certificate cannot be found.]
	[+2?If the related certificate cannot be found, or the public key cannot be extracted from it.]
	[+3?If the public key of the related certificate does not match the one in the key pair for the certificate.]
	[+>=10?If an error occures during header generation/serialization.]
}
\n\n\avnameCFG\a \avnamePH\a \aURL\a \adomain\a [\aSUFFIX\a]
'
function prepareCertPH {
	typeset -n CFG=$1 PH=$2
	typeset URL="$3" DOM=$4 SFX="$5" V PUBKEY

	PH=
	CFG[DOMAIN_ASCII]="${DOM}"
	getKeyFilename CFG V 1
	[[ -r $V ]] || return 1

	PUBKEY=${ ${CFG[OPENSSL]} x509 -in "${V%key}crt" -pubkey -noout ; }
	if (( $? )); then
		Log.fatal "Skipping certficate revocation for '$X'."
		return 2
	fi
	# force re-read
	CFG[JWS-PH-JWK"${SFX}"]= 	CFG[JWS-PH-KID"${SFX}"]=
	CFG[KEY"${SFX}"]=	CFG[KEY-PUB"${SFX}"]=

	getPublicKey CFG "${SFX}"
	if [[ ${PUBKEY} != ${CFG[KEY-PUB${SFX}]} ]]; then
		Log.fatal "The public key of '${V%key}crt' does not match the" \
			"public key of '$V' - certificate revocation skipped."
		return 3
	fi

	prepareJWS_PH CFG "${SFX}" || return 10

	# protected header
    JSON.setVal ${CFG["PH-NONCE${SFX}"]} "${CFG[NONCE]}" || return 11
    JSON.setVal ${CFG["PH-URL${SFX}"]} "${URL}" || return 12
    JSON.toString ${CFG["JWS-PH-JWK${SFX}"]} PH || return 13
    str2base64url CFG PH || return 14
}

Man.addFunc prepareDefaultPH '' '[+NAME?prepareDefaultPH - prepare the protected header for a new ACME request using the private key of the account in use.]
[+DESCRIPTION?Just a wrapper around \bprepareJWS_PH\b \avnameCFG\a, which in addition updates its Nonce value to \avnameCFG\a[NONCE]] and its URL value to \aURL\a. If \avnameCFG\a[IS_LE]] != 0 or \aforceJWK\a is set to a non-empty value, a protected header for Boulder, otherwise one according to the ACME standard gets created, base64url encoded and finally stored to \avnamePH\a.]
\n\n\avnameCFG\a \avnamePH\a \aURL\a [\aforceJWK\a]
'
function prepareDefaultPH {
	typeset -n CFG=$1 PH="$2"
	typeset URL="$3" FORCE_JWK="$4"

	PH=
	prepareJWS_PH CFG || return 1

	# protected header
	JSON.setVal ${CFG[PH-NONCE]} "${CFG[NONCE]}" || return 10
	JSON.setVal ${CFG[PH-URL]} "${URL}" || return 11
	if (( CFG[IS_LE] )) || [[ -n ${FORCE_JWK} ]]; then
		JSON.toString ${CFG[JWS-PH-JWK]} PH || return 12	# boulder: no kid
	else
		checkAccountUrl CFG || return 13;
		JSON.setVal ${CFG[PH-KID]} "${CFG[ACCOUNT-URL]}"
		JSON.toString ${CFG[JWS-PH-KID]} PH || return 14
	fi
	str2base64url CFG PH || return 15
}

Man.addFunc showCerts '' '[+NAME?showCerts - show the contents of PEM fomatted certificates.]
[+DESCRIPTION?Find the certificate files for \avnameCFG\a[DOMAIN]] (see \bfindCerts()\b) and show their contents as human readable text.]
\n\n\avnameCFG\a
'
function showCerts {
	typeset -n CFG=$1
	typeset -A TBD
	integer COUNT
	typeset X

	findCerts CFG TBD "${CFG[DOMAINS]//,/ }"
	if (( ${#TBD[@]} == 0 )); then
		 Log.info 'No certificates found.'
		return 0
	fi
	for X in ${!TBD[@]} ; do
		Log.info "$X"
		${CFG[OPENSSL]} x509 -in "$X" -noout -text
	done
}

Man.addFunc showRemoteCert '' '[+NAME?showRemoteCert - show the contents of the certificate for the given hosts]
[+DESCRIPTION?Connect to each given \ahostname\a via SSL/TLS, extract the certificate of the server and print it out as human readable text. If the connection to a port != 443 is needed, just append \b:\b\aport\a to the related \ahostname\a.]
\n\n\avnameCFG\a \ahostname\a ...
'
function showRemoteCert {
	typeset -n CFG=$1
	typeset F=${LE_TMP}/r.crt OSSL="${CFG[OPENSSL]}"
	
	shift
	for X in "$@" ; do
		[[ $X =~ : ]] || X+=':443'
		print | ${OSSL} s_client -connect $X -servername ${X%:*} 2>/dev/null |\
			${CFG[SED]} -n -e '/BEGIN CERTIFICATE/,/END CERTIFICATE/ p' >$F
		if [[ -s $F ]]; then
			Log.info "$X"
			${OSSL} x509 -in $F -text -noout
		else
			Log.fatal "$X failed"
		fi
	done
}

# 7.6
Man.addFunc revokeCerts '' '[+NAME?revokeCerts - revoke certificates.]
[+DESCRIPTION?Find the certificate files for \avnameCFG\a[DOMAIN]] (see \bfindCerts()\b) and revoke them using their corresponding key pair. If it is missing or an error occurs, a second try is made using the domain authorization based method. The exit code is the number of remaining, not yet revoked certificates.]
\n\n\avnameCFG\a
'
function revokeCerts {
	typeset -n CFG=$1
	integer I NOW=${ printf '%(%s)T' now ; } COUNT
	typeset -A TBD CERTS DOMS
	typeset A T V X CRT URL

	getDirectory CFG
	findCerts CFG TBD "${CFG[DOMAINS]//,/ }"

	for X in "${!TBD[@]}" ; do
		if checkCert CFG T "$X" -${NOW} ; then
			I=0
			for V in $T ; do
				(( I == 0 )) && CERTS["$V"]="$T" && (( I++ ))
				DOMS["$V"]=1
			done
		fi
	done
	COUNT=${#CERTS[@]}
	if (( COUNT == 0 )); then
		 Log.info 'All scanned certificates are already expired.' \
			'No need to revoke any.'
		return 0
	fi

	# payload [recycle bin]
	V=
	JSON.newNumber L "${CFG[REASON]:-0}" && return 10 || V="reason $L"
	JSON.newString CID 'unset' && return 11 || V+=" certificate ${CID}"
	if (( CFG[IS_LE] )); then
		# https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.6
		JSON.newString L 'revoke-cert' && return 14 || V+=" resource $L"
	fi
	JSON.newObject PLID && return 12
	JSON.setVal ${PLID} $V || return 13
	URL=${CFG[URL-revoke]}

	# server MUST also consider a revocation request valid if it is signed with
	# the private key corresponding to the public key in the cert. Try this 1st:
	for (( I = 0; I < 2; I++ )); do
		(( I == 0 )) && SFX='-TMP' || SFX=
		for X in ${!CERTS[@]} ; do
			if (( I == 0 )); then
				prepareCertPH CFG PH "${URL}" "$X" "${SFX}" || continue
				V=${CFG["KEY-FILE${SFX}"]}
			else
				prepareDefaultPH CFG PH "${URL}" 1 || continue
				CFG[DOMAIN_ASCII]="$X"
				getKeyFilename CFG V 1
			fi
	
			PL=
			T="${LE_TMP}/crt.der"
			if ! ${CFG[OPENSSL]} x509 -in "${V%key}crt" -outform DER -out "$T"
			then
				# should not happen unless no space left on device etc. ..
				Log.fatal "Skipping certficate revocation for '$X'."
				CERT["$X"]=
				continue
			fi
			file2base64url CFG CRT "$T" || continue
			JSON.setVal ${CID} "${CRT}"
			JSON.toString ${PLID} PL || return 14
	
			createSig CFG T PL "${PH}" "${SFX}" || return 20
	
			newRequestBody T "${PH}" "${PL}" "$T" || return 30
	
			unset RESULT PARAMS ; typeset -A RESULT PARAMS
			(( VERB )) && Log.info "Requesting cert revocation for '$X' ..."
			PARAMS=( [URL]="${URL}" [METHOD]='POST' [DATA]="$T" )
			fetch CFG RESULT PARAMS
			check403 RESULT
	
			V="for '$X'"
			set -- ${CERTS["$X"]}
			shift
			[[ -n $1 ]] && V+=" ($*)"
	
			integer SC=${RESULT[STATUS_CODE]}
			if (( SC == 202 || SC == 200 )); then
				Log.info "Certificate $V revoked."
			elif (( SC == 409 )); then
				Log.info "Certificate $V already revoked."
			else
				V="Certificate revocation $V failed"
				[[ ${RESULT[_RES_detail]} ]] && \
					V+=" with '${RESULT[_RES_detail]}'"
				Log.fatal "$V."
			fi
			if (( SC == 202 || SC == 200 || SC == 409 )); then
				(( COUNT-- ))
				CFG[DOMAIN_ASCII]="$X"
				getKeyFilename CFG V 1
				mv "${V%.key}.crt" "${V%.key}.revoked"
			fi
		done
		(( COUNT == 0 || I == 1 )) && break

		unset DOMS TBD; typeset -A DOMS TBD

		for X in ${!CERTS[@]} ; do
			[[ -z ${CERTS["$X"]} ]] && continue
			TBD["$X"]="${CERTS[$X]}"
			for T in ${CERTS[$X]}; do
				DOMS["$T"]=1
			done
		done
		unset CERTS
		typeset -n CERTS=TBD
		CFG[DOMAINS]="${!DOMS[@]}"
		if [[ -n ${CFG[DOMAINS]} ]]; then
			# the account must either have authorization for all related
			# domains or be the account, that issued the certificate
			authDomain CFG	# go as far as we can
		fi
	done
	return ${COUNT}
}

Man.addFunc doMain '' '[+NAME?doMain - the main entry point of the script]'
function doMain {
	typeset -A CFG
	integer ERR
	typeset X A

	if [[ -n ${OPTS[SRC]} ]]; then
		A=
		for X in ${OPTS[SRC]}; do
			[[ $X == 'ALL' ]] && A=${ typeset +f; } && break
			(( CFG["$X"] )) && continue
			A+=" $X"
			CFG["$X"]=1
		done
		typeset -f $A
		return 0
	fi
	(( CMD )) || { showUsage ; return 1; }

	set --default --braceexpand --globstar --pipefail
	getConfig CFG || return $?
	checkBinaries CFG || return $(( $? + 10 ))

	(( CMD & CMDS[cdate] )) && { checkDate "$@" ; return $?; }
	(( CMD & CMDS[alist] )) && { listAccounts CFG ; return $?; }
	(( CMD & CMDS[dlist] )) && { listDomains CFG ; return $?; }
	(( CMD & CMDS[clist] )) && { listCerts CFG ; return $?; }
	(( CMD & CMDS[csummary] )) && { certSummary CFG ; return $?; }
	(( CMD & CMDS[cshow] )) && { showCerts CFG ; return $?; }
	(( CMD & CMDS[clive] )) && { showRemoteCert CFG "$@" ; return $?; }
	if (( CMD & CMDS[config] )); then
		dumpArray CFG ${CFG_FILTER}
		return 0
	fi
	if (( CMD & CMDS[base64dec] )); then
		X="$1"
		if ! base64url2str CFG X "$2" ; then
			Log.fatal 'failed'
			return 2
		fi
		[[ -z $2 ]] && print -- "$X"
		return 0
	fi

	(( CMD & CMDS[register] )) && { accountCreate CFG ; return $?; }
	(( CMD & CMDS[find] )) && { accountFind CFG ; return $?; }
	(( CMD & CMDS[info] )) && { accountInfo CFG ; return $?; }
	(( CMD & CMDS[update] )) && { accountUpdate CFG ; return $?; }
	(( CMD & CMDS[chkey] )) && { accountChangeKey CFG ; return $?; }
	(( CMD & CMDS[unregister] )) && { accountClose CFG ; return $?; }
	if (( CMD & CMDS[authorize] || CMD & CMDS[cert] )); then
		authDomain CFG || return $?
	fi
	(( CMD & CMDS[cert] )) && { getCert CFG ; return $?; }
	(( CMD & CMDS[renew] )) && { renewCerts CFG ; return $?; }
	# TBD
	(( CMD & CMDS[unauthorize] )) && { unauthDomain CFG ; return $?; }
	(( CMD & CMDS[revoke] )) && { revokeCerts CFG ; return $?; }

	return 0
}

Man.addFunc command '' '[+NAME?supported commands]
[+DESCRIPTION?The following commands (or operations) are currently supported:]{
	[+?][+config?Dump the current configuration in use to the standard output and exit.]
	[+?][+register?Setup a new local account by creating a new keypair (if not already done), and register it on the ACME server. The account used by default is named \bdefault\b but can be adjusted using the \b-a \b\a...\a option. The local account as well as all related information including public/private keys and certificats gets stored in the config directory in use. The local account here has nothing to do with the OS account database in use. Anyway, to avoid too much clutter this document refers to it simply as \baccount\b.]
	[+?][+?One needs to register on an ACME server, before one may initiate other operations like ordering a new certificate. Using more than a single account with a certain ACME server is ok, but using a single acount with different ACME servers is not recommended/not supported by this script. If one needs to use more than one ACME server, a separate config directory (see option \b-c \b\a...\a) should be used for each ACME entity.]
	[+?][+?On registration (as well on update) the script expects an e-mail address to be set (either given via CLI option or per config file), which gets put into the contact information for the server. If the server allows to register without an e-mail address, one may use a dash (\b-\b) instead.]
	[+?][+info?Get account information from the ACME server.]
	[+?][+update?Replace the contact information for the account on the ACME server. An e-mail address is required to be set - see \bregister\b for more details.]
	[+?][+chkey?Create a new key pair for the account in use and replace the related public key on the ACME server. Optionally one may specify a file with the new private key (which also contains the public key) via CLI option \b-k \b\a...\a to avoid automatic creation of a new key pair.]
	[+?][+unregister?Deactivate an account on the ACME server. On success the related ACME server does not allow any operation related to it, and thus e.g. any certificates assigned to this account cannot be managed anymore. So think twice before doing this!]
	[+?][+alist?List the account names of all known active accounts.]
	[+?][+find?Find the account URL to be used for ACME operations. Not really interesting for an end-user, but may be for other scripts.]
	[+?][+authorize?To get a certificate for one or more domains, one needs to prove, that the account being used has control over the domain(s) either explicitly specified via option \b-d \b\a...\a or implicitly by an existing certificate file. One may use this command to obtain the required authorization(s).]
	[+?][+?Wrt. HTTP based checks, this scripts asks the ACME server for a challenge, prepares the answer and asks the server to check it immediately. Than the server just looks for \bhttp://\b\adomain\a\b:80/'"${DEFAULT[PREFIX]}"'/\atoken\a, whereby \atoken\a contains the prepared answer. This script is able to answer such requests directly (use option \b-p \b\aport_num\a), or by default to just store the answers in a given directory, which e.g. gets served by a full blown webserver like Apache httpd. See docs/setup-example.md to get an idea.]
	[+?][+?Note that the script automatically invokes this command when needed.]
	[+?][unauthorize?Use this command to deactivate a pending or valid authorization for one or more domains.]
	[+?][+dlist?List domains configured/touched by this script so far.]
	[+?][+cert?Get a new certificate for the domain(s) given via option \b-d \b\a...\a. The first domain specified using this option will be used as \bCN\b (Common Name) of the new certificate and used locally to store meta information as well the certificate and related keys for it (which your SSL/TLS application needs). The used \aprefix\a for related files is \aconfig_dir\a\b/\b\aca_name\a\b/r-\b\adomain\a.]
	[+?][+?If a key pair for the new certificate already exists (a PEM formatted file named \aprefix\a\b.key\b), this will be used, otherwise a new one gets created.]
	[+?][+?If a certificate submission request (CSR) config template named \aprefix\a\b.cfg\b exists, this script tries to use it as base for the new CSR config, which in turn gets stored as \aprefix\a\b.txt\b. The CSR used to request the certificate gets stored PEM formatted as \aprefix\a\b.csr\b. If no CSR config template exists, the internal template will be used, which is at least for LE servers all you need.]
	[+?][+?On success the new certificate gets stored PEM formatted as \aprefix\a\b.crt\b.]
	[+?][+renew?Re-new a certificate, which expires soon. Soon is by default \b'"${DEFAULT[DAYS]}"'\b days, but can be adjusted via option \b-X \b\adays\a and thus lets you force the renewal of a certificate. The command gets applied to all certificates with the common names (\bCN\b) specified via option \b-d \b\a...\a. Note that this command accepts as argument for this option the name of a PEM formatted certificate file instead of a domain, too. In this case all relevant domains are extracted from the certificate automatically. If the special word \ball\b is used, the common names of all certificates shown with the command \bclist\b get selected, too.]
	[+?][+revoke?Revoke all certificates with the common names (\bCN\b) specified via option \b-d \b\a...\a. Note that this command accepts as argument for this option the name of a PEM formatted certificate file instead of a domain, too. Per default the private key of the certificate (\aprefix\a\b.key\b) will be used to request the revocation. If not available, the \bauthorize\b command gets invoked for all relevant domains of the related certificate and on success the certificate revocation request made based on the domain authorizations.]
	[+?][+clist?List the common names of all certificates aquired so far.]
	[+?][+csummary?Show a summary for each certificate aquired so far. The character in the first row has the following meaning: \bV\b .. \bvalid\b, \bN\b .. \bnot yet valid\b, and \bX\b .. \bexpired\b.]
	[+?][+cshow?Show the contents of the certificate specified via option \b-d \b\a...\a as human readable text. Note that this command also accepts the path to a PEM formatted file as option argument as well.]
	[+?][+clive?Show the contents of the certificate of the given host (operand 1) as human readable text. If the related service is running on a port != 443, append \b:\b\aport\a to the end of the hostname in question. E.g. "'"${PROG}"' -c clive my.do.main:636".]
	[+?][+base64dec?Decode the given string (operand 1) according to RFC 7515. If operand 2 is given, it gets taken as a file path and the decoded value gets printed into that file. Otherwise the value gets printed to stdout. Exposed for developers, only.]
}
[+?A command refers always to a single account and a single ACME server. Both can be specified via CLI option or via a configuration file. If none are set, the script will use the related builtin fallbacks.]
'

unset ${CFG_FILTER}		# avoid that this screws up something
Man.addFunc MAIN '' '[+NAME?'"${PROG}"' - ACME client]
[+DESCRIPTION?This script is an \bAutomatic Certificate Management Environment\b (\bACME\b) tool which can be used to go through all steps required to register ACME accounts, obtain, update, revoke SSL certificates and unregister ACME accounts on demand using the \b'"Let’s Encrypt"'\b Certificate Authority (CA) servers and possibly others following RFC 8555. It supports the challenge-response mechanism \bhttp-01\b and is intended to be used for mass deployment and maintenance of '"Let’s Encrypt"' certificates. It can be even used as a supporting library.]
[+?On start the script initializes its configuration using builtin defaults. Than it reads in the \ble.conf\b file (see "'"${PROG} -H LE_ENV"'" for more information) and augments/overwrites the defaults. Finally any relevant options supplied via CLI will augment/overwrite related configuration values to use during this run. All CLI options, which have an \ble.conf\b equivalent are tagged with "See \bLE_ENV\b". Use the command shown before to get the details - the default man page will show a short description, only.]
[+?The script leverages a lot of useful features provided by ksh93 and thus make it much more compact, efficient, self-contained, easier to maintain incl. troubleshooting + testing and allows a consistent self-documentation. Using other shells than ksh93 - e.g. bash, zsh, pdksh, mksh, etc. - to run this script is neither intended nor supported and probably will not work anyway, because they are not ksh93 compatible.]
[h:help?Print this help and exit immediately.]
[F:functions?Print out a list of all defined functions and exit immediately. Just invokes the \btypeset +f\b builtin.]
[H:usage]:[function?Show the usage information for the given function if available and exit immediately. As long as not explicitly mentioned, the return value of each function is 0 on success and != 0 otherwise. See also option \b-F\b.]
[S:source]:[fname_list?Show the source code of all functions specified by the comma or whitspace separated list of function names and exit.]
[T:trace]:[fname_list?A comma or whitspace separated list of function names, which should be traced during execution.]
[+?]
[A:acme-ca]:[name?Use the ACME-CA with the given \aname\a and its related config. See LE_ENV:\bCA\b.]
[B:not-after]:[date?When getting/renewing a certificate, ask to set its end of validity period to \adate\a.  See LE_ENV:\bNOT_AFTER\b.]
[C:cfgdir]:[path?The directory, where this script stores all its data incl. configuration. Ideally it should not exist when invoking this script for the first time and should be kept secure, because private keys etc. will be stored there. Also note, that this script sees this directory as its own property and thus overwrites or removes any files as needed \bwithout notice\b. Default: '"${DEFAULT['CFG-DIR']}"'.]
[D:dumpdir]:[path?If the directory \apath\a exists, fake HTTP responses by looking up related \abasename\a\b.header\b and \abasename\a\b.body\b. If both are there they get used instead of actually making a real HTTP request. Use for testing/troubleshooting, only.]
[E:expired?Treat all cached status records of domain authorizations as expired and query the current state from ACME servers as needed. SEE LE_ENV:\bFORCE_STATUS\b.]
[K:keep?Keep the temp directory used during the run and show a message, that it should be deleted if not needed anymore.]
[P:privilege]:[utility?If higher privileges are needed (e.g. when listening on a privileged port), prefix the related command with the given \autility\a. See LE_ENV:\bPFEXEC\b.]
[R:re-auth?Ignore the current authorization status of all related domains and re-authorize if needed. SEE LE_ENV:\bFORCE_AUTH\b.]
[U:http-util-cfg]:[path?Pass \apath\a as config file to use to the http-util. See LE_ENV:\bUTIL_CFG\b.]
[X:expire]:[days?If a certificate expires in less than the given \adays\a, consider it for renewal. Only relevant with \b-c renew\b. See LE_ENV:\bDAYS\b.]
[Z:cert-extension]:[ext?If a new certificate gets copied to the cert directory (see option \b-z \b\apath\a), use the given extension \aext\a instead off \b.crt\b. See LE_ENV:\bCERT_EXT\b.]
[a:account]:[name?Use the account \aname\a and related config. See LE_ENV:\bACCOUNT\b.]
[b:not-before]:[date?When getting/renewing a certificate, ask to set the begin of its validity period to \adate\a.  See LE_ENV:\bNOT_BEFORE\b.]
[c:command]:[command?Execute the given \acommand\a. See "'"${PROG} -H \bcommand\b"'" for more information.]
[d:domain]:[list?A comma separated list of domains, for which the specified command should be executed. See also LE_ENV:\bDOMAINS\b.]
[e:email]:[address?The e-mail \aaddress\a to use, when a new account gets registered (i.e. required if \b-c register\b). See LE_ENV:\bEMAIL\b.]
[k:key]:[path?Use the private key stored in \apath\a (instead of generating a new one on-the-fly) to replace the current key in use. Ignored for all but \bchkey\b commands. See LE_ENV:\bNEWKEY\b.]
[m:my-response?When needed, it asks to start your own client or script to answer challenge response requests from ACME servers. See also LE_ENV:\bMY_RESPONSE\b.]
[p:port]:[num?Use the internal web server to listen on port \anum\a for authorization requests from ACME servers when needed. See LE_ENV:\bPORT\b.]
[r:reason]:[num?Optional reason code for certificate revocation. Allowed values are 0..10, except 7. See LE_ENV:\bREASON\b.]
[s:save?Save all HTTP[S]] responses to the dump directory, i.e. wrt. the -D .. option, turn read into write. Use for testing/troubleshooting, only.]
[u:http-util]:[path?Force \apath\a to be used to get and post data via HTTP[S]]. See LE_ENV:\bUTIL\b.]
[v:verbose?Annoy me with the details of what the script is doing.]
[z:cert-dir]:[path?Copy all new certificates to \apath\a/\adomain\a\b.crt\b as well. See LE_ENV:\bCERT_DIR\b.]
[+EXAMPLES?]
[+?\b1)\b Get a new certificate:]{
[+?'"${PROG}"' -d my.do.main,alias1.do.main,alias2.do.main -c cert]
}
[+?\b2)\b Renew all certificates already obtained, if needed:]{
[+?'"${PROG}"' -d all -c renew]
}
[+?\b3)\b Revoke the certificate for my.do.main:]{
[+?'"${PROG}"' -d my.do.main -c revoke]
}
[+ENVIRONMENT VARIABLES?The following environment variables are honored:]{
	[+PATH?Used to find external tools like openssl, curl or wget.]
	[+LOGNAME?The login name of the user running this script. All POSIX compatible OS will set it automatically on login.]
	[+HOME?The home directory of the user running this script. All POSIX compatible OS will set it automatically on login.]
	[+OPENSSL?The path to the \bopenssl\b(1) binary to use. Per default it gets picked up via \bPATH\b automatically.]
	[+LC_MESSAGES?If set, the script asks the ACME server to send text messages  in a related language (but text encoding stays UTF-8).]
	[+TESTING?If set and not empty, this script behaves like a library: It does basic initialization and CLI option processing and not more. So one may source this file into its own script, optionally call \bgetConfig\b() and \bcheckBinaries\b() and start using/testing the functions as needed.]
	[+TESTING_LIB?Same as \bTESTING\b but skips in addition CLI option processing and variable initialization.]
}
[+SEE ALSO?"\b'"${PROG} -H LE_ENV"'\b", \b"'"${PROG} -H command"'\b", https://letsencrypt.org/docs/acme-protocol-updates/ , https://letsencrypt.org/docs/rate-limits/ , https://letsencrypt.org/docs/expiration-emails/ , \bopenssl\b(1), \bcurl\b(1) or \bwget\b(1), \bpfexec\b(1m) or \bsudo\b(8), \bksh93\b(1).]
[+NOTES?]
[+?The script tries to create any files and directories as needed, with the permissions it thinks are appropriate. Once they exist, it does not change ownership or permissions - it just expects, that they are still read/writeable on consecutive invocations of the script. So be careful when changing them!]
[+?The script does not differentiate/associates a certain account name alias private key with a certain ACME server instance. Therefore you should never share one and the same key between ACME servers.]
[+?External key binding is not yet supported.]
[+?For all the crypto work \bopenssl\b(1) is used. Its pseudo random number generator (PRNG) seeding uses the file \b~/.rnd\b or \b.rnd\b. For more information see \brand\b(1) or \brand\b(1openssl).]
[+?Because one can use this script as a normal library, it does not have any pre- or post-run hooks. If needed, just write a script, which a) declares your pre- and post-run function, b) sets TESTING=1, c) sources in this script, d) calls pre-run, doMain and finally the post-run function.]
[+?To get the latest released version of this script, just get \bhttp://iks.cs.ovgu.de/~elkner/acme/acme.ksh\b. Additional information is available via \bhttps://github.com/jelmd/acme-ksh/\b.]
'
if [[ -z ${TESTING_LIB} ]]; then
	unset OPTS CMD ; typeset -A OPTS CMDS=(
		[config]=1						# dump configuration
		# account ops
		[register]=2  [unregister]=4 [find]=8 [info]=16 [update]=32 [chkey]=64
		[authorize]=128 [cert]=256 [renew]=512 [unauthorize]=1024 [revoke]=2048
		[cdate]=16384
		[alist]=32768
		[dlist]=65536
		[base64dec]=131072
		[cshow]=262144
		[clist]=524288
		[csummary]=1048576
		[clive]=2097152
	)		
	. checkEnv
	integer ERR=0 VERB=0 CMD=0
	X="${ print ${Man.FUNC[MAIN]} ; }"
	while getopts "${X}" option ; do
		case "${option}" in
			h) showUsage MAIN ; exit 0 ;;
			F) typeset +f ; exit 0 ;;
			H)  if [[ ${OPTARG%_t} != ${OPTARG} ]]; then
					${OPTARG} --man   # self-defined types
				else
					showUsage "${OPTARG}"   # function
				fi
				exit 0
				;;
			T)	if [[ ${OPTARG} == 'ALL' ]]; then
					OPTS[DEBUG-FN]="${ typeset +f ; }"
					typeset -ft ${OPTS[DEBUG-FN]}
					set -x
				else
					OPTARG="${OPTARG//,/ }"
					typeset -ft ${OPTARG}
					OPTS[DEBUG-FN]+=" ${OPTARG}"
				fi
				;;
			A) OPTS[CA]="${OPTARG}" ;;
			B) OPTS[NOT_AFTER]="${OPTARG}" ;;
			C) OPTS[CFG-DIR]="${OPTARG}" ;;
			D) OPTS[TEST-DIR]="${OPTARG}" ;;
			E) OPTS[FORCE_STATUS]=1 ;;
			K) OPTS[KEEP]=1 ;;
			P) OPTS[PFEXEC]="${OPTARG}" ;;
			R) OPTS[FORCE_AUTH]=1 ;;
			S) OPTS[SRC]+=" ${OPTARG//,/ }" ;;
			U) OPTS[UTIL_CFG]="${OPTARG}" ;;
			X) OPTS[DAYS]="${OPTARG}" ;;
			Z) OPTS[CERT_EXT]="${OPTARG}" ;;
			a) OPTS[ACCOUNT]="${OPTARG}" ;;
			b) OPTS[NOT_BEFORE]="${OPTARG}" ;;
			c)	if (( CMDS[${OPTARG}] )); then
					(( CMD |= CMDS[${OPTARG}] )) && continue
				elif [[ -n ${OPTARG} ]]; then			# paranoid ?
					for T in ${!CMDS[@]} ; do
						[[ $T == ${OPTARG}* ]] && (( CMD |= CMDS[$T] )) && T= \
							&& break
					done
					[[ -z $T ]] && continue
				fi
				Log.fatal "Unknown ACME command '${OPTARG}'"
				(( ERR++ ))
				;;
			d) OPTS[DOMAINS]+=",${OPTARG}" ;;
			e) OPTS[EMAIL]="${OPTARG}" ;;
			k) OPTS[NEWKEY]="${OPTARG}" ;;
			m) OPTS[MY_RESPONSE]=1 ;;
			p) OPTS[PORT]="${OPTARG}" ;;
			r) OPTS[REASON]="${OPTARG}" ;;
			s) OPTS[HTTP-DUMP]=1 ;;
			u) OPTS[UTIL]="${OPTARG}" ;;
			v) VERB=1 ;;
			z) OPTS[CERT_DIR]="${OPTARG}" ;;
			*) showUsage ;;
		esac
	done
	X=$((OPTIND-1))
	shift $X
	OPTIND=1
	
	(( ERR )) && Log.fatal "Exiting dueto errors. No changes were made." && \
		return ${ERR}
	unset X ERR
fi

if [[ -z ${TESTING} && -z ${TESTING_LIB} ]]; then
	unset LE_TMP; typeset LE_TMP ; trap cleanup EXIT
	doMain "$@"
	I=$?
	(( I && ! CMD & CMDS[renew] )) && Log.fatal 'Exiting dueto errors.'
	return $I
else
	:
fi

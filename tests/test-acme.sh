#!/bin/sh
cd ${ dirname $0; }

function t_getChallenges {
	[[ -z ${CFG[TEST-DIR]} ]] && CFG[TEST-DIR]='/tmp/dumps'
	[[ -d ${CFG[TEST-DIR]} ]] || mkdir -p "${CFG[TEST-DIR]}"
	typeset F=${CFG[TEST-DIR]}/new-authz.body
	if [[ ! -e $F ]]; then
		CFG[HTTP-DUMP]=1
		CFG[DOMAINS]='foo.bar'
		authDomain CFG
	fi
	V=$(<"$F")
	[[ -z $V ]] && return 1

	typeset -A RES
	typeset BUF JID
	print -- "$V" | JSONP.readValue JID BUF
	getChallenges ${JID} RES || return 2
	dumpArray  RES
	[[ ${RES[dns-01-status]} == 'pending' ]] && Log.info ok || Log.warn failed
}

export TESTING=1
source acme.sh

typeset -A CFG
getConfig CFG || exit 1
checkBinaries CFG || exit 2
VERB=1

#createPrivateKey /tmp/foo.key P-2568 &&  exit
#createPrivateKey /tmp/foo.key P-256 || exit
#createPrivateKey /tmp/foo.key RSA512-2048 || exit
#createPrivateKey /foo.key P-256 && exit
#getPrivateKey CFG || exit 3
#prepareJWS_PH CFG || exit 4
#TXT='foobar leckmich'
#SIG=
#sign CFG TXT SIG
CFG[EMAIL]='foobar@example.com'
CFG[EMAIL]='-'
#CFG[EMAIL]='foobar@dev.null'
#accountCreate CFG || exit 5
#accountFind CFG || exit 6
#accountInfo CFG || exit 7
#accountUpdate CFG || exit 8

function t_jwk_thumbprint {
	# example from RFC 7638
	X='{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}'
	shaHash X 256
	[[ $X == '37:36:cb:b1:78:7c:b8:30:9c:77:ee:8c:37:05:c5:e1:6f:fb:9e:85:97:15:90:1f:1e:4c:59:b1:11:82:f5:7b' ]] || return 1
	hexdump2str X
	str2base64url X 1
	[[ $X == 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs' ]] || return 2
}
#t_jwk_thumbprint
#accountChangeKey CFG || exit 10
#accountClose CFG || exit 11
t_getChallenges || exit 12
#Log.warn Check; read

Log.info 'fertsch'

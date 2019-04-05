function test2str {
	typeset -n S=$1
	typeset X=${S:1:${#S}-2} T
	typeset -i16 C
	for C in ${X//,} ; do
		T+='\x'${C:3}
	done
	S=${ printf "$T" ; }
}

# see https://tools.ietf.org/html/rfc7515#appendix-A.1
X='[123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125]'
test2str X
[[ $X != $'{"typ":"JWT",\r\n "alg":"HS256"}' ]] && \
	Log.fatal "test2str failed"

# TBD: https://tools.ietf.org/html/rfc7516#appendix-A.1
# TBD: https://tools.ietf.org/html/rfc7517#appendix-A.1
# TBD: https://tools.ietf.org/html/rfc7518#appendix-B.1

print ${.sh.file} done.

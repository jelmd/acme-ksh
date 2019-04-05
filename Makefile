SRC = script.sh 
INCLUDES = includes/AcmeHTTPServer.py \
	includes/json.sh \
	includes/log.kshlib \
	includes/man.kshlib
PROG = acme.ksh
GENERATOR = generate.sh

$(PROG): $(GENERATOR) $(SRC) $(INCLUDES) Makefile
	$(GENERATOR) $(SRC) >$@
	chmod 755 $@

clean:
	rm -f $(PROG)

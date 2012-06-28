all:
	./rebar compile

doc:
	./rebar doc

pkg:	all doc
	tetrapak pkg:ipkg

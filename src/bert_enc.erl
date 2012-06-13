-module(bert_enc).

-export([encode/1,
	 decode/1]).


encode(X) ->
    bert:to_binary(X).

decode(X) ->
    bert:to_term(X).

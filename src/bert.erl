%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @doc
%%%    BERT encode/decode
%%% @end
%%% Created : 14 Dec 2011 by Tony Rogvall <tony@rogvall.se>

-module(bert).

-export([to_binary/1, to_term/1]).
-export([to_berp/1]).
-export([encode/1, decode/1]).
-export([time/0, time/1, time_to_now/1]).
-export([regex/1, regex/2, regex_compile/1]).

-include("bert.hrl").

-type now() :: {M::non_neg_integer(),S::0..999999,U::0..999999}.

%%--------------------------------------------------------------------
%% @doc
%%    Convert an Erlang term to BERT binary
%% @end
%%--------------------------------------------------------------------
-spec to_binary(Term::term()) -> binary().
		       
to_binary(Term) ->
    term_to_binary(encode(Term)).

%%--------------------------------------------------------------------
%% @doc
%%    Convert BERT binary to an Erlang term
%% @end
%%--------------------------------------------------------------------

-spec to_term(Bin::binary()) -> term().

to_term(Bin) when is_binary(Bin) ->
    decode(binary_to_term(Bin)).

%%--------------------------------------------------------------------
%% @doc
%%    convert an Erlang term to a BERP, like BERT but with a 4 byte
%%    length header.
%% @end
%%--------------------------------------------------------------------

-spec to_berp(Term::term()) -> binary().

to_berp(Term) ->
    Binary = term_to_binary(encode(Term)),
    Size = byte_size(Binary),
    [<<Size:32>>, Binary].

%%--------------------------------------------------------------------
%% @doc
%%    Get current time, encoded in bert time format
%% @end
%%--------------------------------------------------------------------
-spec time() -> #bert_time{}.

time() ->
    time(erlang:now()).

%%--------------------------------------------------------------------
%% @doc
%%    Convert erlang now format into bert time format
%% @end
%%--------------------------------------------------------------------
-spec time(T::now()) -> #bert_time{}.

time({M,S,U}) ->
    #bert_time { mega=M, sec=S, usec=U }.

%%--------------------------------------------------------------------
%% @doc
%%    Convert bert_time format into erlang now format
%% @end
%%--------------------------------------------------------------------
-spec time_to_now(#bert_time{}) -> now().
    
time_to_now(#bert_time { mega=M, sec=S, usec=U }) ->
    {M,S,U}.

%%--------------------------------------------------------------------
%% @doc
%%    Create a bert regex from a source binary string
%% @end
%%--------------------------------------------------------------------
-spec regex(Source::binary()) -> #bert_regex{}.
		   
regex(Source) when is_binary(Source) ->
    #bert_regex { source=Source, options=[] }.

%%--------------------------------------------------------------------
%% @doc
%%    Create a bert regex from a source binary string and options
%% @end
%%--------------------------------------------------------------------
-spec regex(Source::binary(),Options::list(atom())) -> #bert_regex{}.

regex(Source, Options) when is_binary(Source), is_list(Options) ->
    #bert_regex { source=Source, options=Options }.

%%--------------------------------------------------------------------
%% @doc
%%    Compile a BERT regex 
%% @end
%%--------------------------------------------------------------------

%% fix return type!
-spec regex_compile(#bert_regex{}) -> binary().
			   
regex_compile(#bert_regex { source=Source, options=Options }) ->
    re:compile(Source, Options).

%%--------------------------------------------------------------------
%% @doc
%%    decode Term -> BERT
%% @end
%%--------------------------------------------------------------------
-spec encode(X::term()) -> term().
		    
encode(X) when is_number(X) -> X;
encode(X) when is_binary(X) -> X;
encode(true)  -> #bert { term=true};
encode(false) -> #bert { term=false};
encode(X) when is_atom(X) -> X;
encode([])    -> #bert { term=nil};
encode(X) when is_record(X, dict, 8) ->
    {bert, dict, encode_proper_list(dict:to_list(X))};
encode(#bert_time { mega=M, sec=S, usec=U }) ->
    if is_integer(M), M >= 0,
       is_integer(S), S>=0, S<1000000, 
       is_integer(U), U >= 0, U<1000000 ->
	    {bert, time, M, S, U }
    end;
encode(#bert_regex { source=S, options=Opt }) ->
    if is_binary(S), is_list(Opt) ->
	    {bert, regex, S, Opt }
    end;
encode(X) when is_tuple(X) -> encode_tuple(size(X), X, []);
encode(X) when is_list(X)  -> encode_proper_list(X).

encode_proper_list([]) ->     [];
encode_proper_list([X]) ->    [encode(X)];
encode_proper_list([X|Xs]) -> [encode(X) | encode_proper_list(Xs)].

encode_tuple(0, _X, L) ->
    list_to_tuple(L);
encode_tuple(I, X, L) ->
    encode_tuple(I-1, X, [encode(element(I,X))|L]).

%%--------------------------------------------------------------------
%% @doc
%%    decode BERT -> Term
%% @end
%%--------------------------------------------------------------------

-spec decode(X::term()) -> term().

decode(X) when is_number(X) -> X;
decode(X) when is_atom(X) -> X;
decode(X) when is_binary(X) -> X;
decode(#bert { term=true}) -> true;
decode(#bert { term=false }) -> false;
decode(#bert { term=nil }) -> [];
decode({bert,dict,List}) ->
    dict:from_list(decode_proper_list(List));
decode({bert,time,M,S,U}) ->
    if is_integer(M), M >= 0,
       is_integer(S), S>=0, S<1000000, 
       is_integer(U), U >= 0, U<1000000 ->
	    #bert_time { mega = M, sec = S, usec = U }
    end;
decode({bert,regex,Source,Options}) ->
    if is_binary(Source), is_list(Options) ->
	    #bert_regex { source=Source, options=Options}
    end;
decode(X) when is_tuple(X) -> decode_tuple(size(X), X, []);
decode(X) when is_list(X)  -> decode_proper_list(X).

decode_proper_list([]) ->     [];
decode_proper_list([X]) ->    [decode(X)];
decode_proper_list([X|Xs]) -> [decode(X) | decode_proper_list(Xs)].

decode_tuple(0, _X, L) ->
    list_to_tuple(L);
decode_tuple(I, X, L) ->
    decode_tuple(I-1, X, [decode(element(I,X))|L]).
    



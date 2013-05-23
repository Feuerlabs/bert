%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
-module(bert_challenge).

-export([authenticate/3,
	 outgoing/2,
	 incoming/2]).
-export([remote_id/1]).

-compile(export_all).

-include_lib("lager/include/log.hrl").

-record(data, {
	  id,
	  chal,
	  key}).

-record(st, {mine = #data{},
	     theirs = #data{}}).

-define(TIMEOUT, 10000).

%%-define(debug(Fmt,A), io:fwrite("~p-~p: " ++ Fmt,[?MODULE,?LINE|A])).

authenticate(Socket, Role, Opts) ->
    try
	?debug("authenticate, client side~n", []),
	%% St = init(ID, MyKey, TheirKey),
	St = init(Opts),
	if Role == client ->
		send_first_challenge(Socket, St);
	   Role == server ->
		await_first_challenge(Socket, St)
	end
    catch
	error:E ->
	    ?error("~p: ERROR: ~p~n", [?MODULE, E]),
	    error
    end.
%% authenticate(Socket, {server, ID, {M,F}}) ->
%%     ?debug("authenticate, server side dynamic~n", []),
%%     St = init(ID, undefined, {M,F}),
%%     await_first_challenge(Socket, St);
%% authenticate(Socket, {server, ID, MyKey, TheirKey}) ->
%%     ?debug("authenticate, server side~n", []),
%%     St = init(ID, MyKey, TheirKey),
%%     await_first_challenge(Socket, St).


outgoing(Data, St) ->
    Tok = make_token(Data, St),
    <<Tok:4/binary, Data/binary>>.

incoming(<<Tok:4/binary, Data/binary>>, St) ->
    case check_token(Tok, Data, St) of
	true ->
	    ?debug("incoming token verified~n"
		   "Data = ~p~n", [Data]),
	    Data;
	false ->
	    ?debug("bad incoming token~n", []),
	    error(bad_token)
    end.

remote_id(#st{theirs = #data{id = ID}}) ->
    ID.

%% client (1)
send_first_challenge(Socket, St) ->
    ?debug("Sending first challenge~n", []),
    {Bin, St1} = init_challenge(St),
    ?debug("Sending_first_challenge result ~p~n", [{Bin, St1} ]),
    exo_socket:send(Socket, Bin),
    await_response(Socket, St1).

%% server (1)
await_first_challenge(Socket, St) ->
    ?debug("await_first_challenge~n", []),
    Data = recv(Socket),
    ?debug("await_first_challenge: data = ~p.", [Data]),
    case recv_challenge(Data, St) of
	error ->
	    ?debug("auth error~n", []),
	    error;
	{Response, St1} ->
	    ?debug("received good challenge~n", []),
	    exo_socket:send(Socket, Response),
	    await_ack(Socket, St1)
    end.

%% client (2)
await_response(Socket, St) ->
    ?debug("await_response~n", []),
    Data = recv(Socket),
   ?debug("await_response: data ~p~n", [Data]),
    case recv_challenge(Data, St) of
	error ->
	    ?debug("auth error~n", []),
	    error;
	{Response, St1} ->
	    ?debug("received good response - auth ok~n", []),
	    exo_socket:send(Socket, Response),
	    {ok, St1}
    end.

%% server (2)
await_ack(Socket, St) ->
    ?debug("await_ack~n", []),
    Data = recv(Socket),
    case recv_challenge(Data, St) of
	error ->
	    ?debug("auth error~n", []),
	    error;
	{_, St1} ->
	    ?debug("received good ack - auth ok.~n", []),
	    {ok, St1}
    end.


rand_bytes(N) ->
    Sz = N*8,
    <<X:Sz/little>> = crypto:strong_rand_bytes(N),
    X.

%% @doc called on either side to initiate
%% init(ID, MyKey, TheirKey) ->
%%     Chal = rand_bytes(4),
%%     #st{mine = #data{id = ID, chal = Chal, key = MyKey},
%% 	theirs = #data{key = TheirKey}}.

init(Opts) ->
    ?debug("~p: init(~p)~n", [?MODULE, Opts]),
    Chal = rand_bytes(4),
    MyId = proplists:get_value(id, Opts, undefined),
    case proplists:get_value(keys, Opts) of
	dynamic ->
	    M = proplists:get_value(mod, Opts, ?MODULE),
	    #st{mine = #data{id = MyId, chal = Chal},
		theirs = #data{key = {M, keys}}};
	{MyK, TheirK} ->
	    #st{mine = #data{id = MyId, chal = Chal, key = MyK},
		theirs = #data{key = TheirK}}
    end.

init_challenge(#st{mine = #data{id = ID, chal = Chal, key = MyKey} = M} = S0) ->
    ?debug("~p: init_challenge(~p)~n", [?MODULE, S0]),

    Tok = make_token_(ID, Chal, MyKey),
    ?debug("~p: init_challenge() Token ~p~n", [?MODULE, Tok]),
    S1 = S0#st{mine = M#data{chal = Chal}},
    ?debug("~p: init_challenge() S1 ~p~n", [?MODULE, S1]),
    {<<Chal:32/little, Tok/binary, ID/binary>>, S1}.

recv_challenge(<<Chal:32/little, Tok:4/binary, P/binary>>,
	       #st{mine = M, theirs = T} = S0) ->
    case keys(P, S0) of
	error -> error;
	{MyKey, TheirKey} ->
	    T1 = T#data{chal = Chal, key = TheirKey},
	    case check_token_(Tok, P, Chal, TheirKey) of
		true ->
		    T2 = case T1#data.id of
			     undefined -> T1#data{id = P};
			     _ -> T1
			 end,
		    #data{id = MyId, chal = MyChal} = M,
		    Tok1 = make_token_(MyId, MyChal, MyKey),
		    %% Tok1 = rand_token(MyChal, M#data.key),
		    {<<MyChal:32/little, Tok1/binary, MyId/binary>>,
		     S0#st{mine = M#data{key = MyKey}, theirs = T2}};
		false ->
		    case check_token_(Tok, P, Chal, MyKey) of
			true ->
			    lager:warning("Keys switched !!!", []);
			false ->
			    ?debug("Wrong key !!!", [])
		    end,
		    error
	    end
    end.

%% If on server side, we may need to fetch the key pair.
keys(ID, #st{theirs = #data{key = {M, F}}}) ->
    ?debug("keys: id ~p, their mf ~p:~p~n", [ID, M, F]),
    case M:F(ID) of
	{_MyKey, _TheirKey} = Res ->
	    ?debug("keys: result ~p~n", [Res]),
	    Res;
	error ->
	    ?debug("keys: error~n", []),
    	    error
    end;
keys(_, #st{theirs = #data{key = Kt}, mine = #data{key = Km}}) when
      is_binary(Kt), is_binary(Km) ->
    ?debug("~p: keys their ~p, mine ~p~n", [Kt, Km]),
    {Km, Kt}.


%% @doc called to generate a token based on payload.
make_token(P, #st{mine = #data{chal = Chal, key = Key}}) ->
    make_token_(P, Chal, Key).

%% @doc called to check a token received from the other side.
check_token(Tok, P, #st{theirs = #data{chal = Chal, key = Key}}) ->
    check_token_(Tok, P, Chal, Key).

rand_token(Chal, Key) ->
    {_,_,US} = os:timestamp(),
    P = <<US:32>>,
    Tok = make_token_(P, Chal, Key),
    <<Tok:4/binary, P/binary>>.

make_token_(P, Chal, Key) ->
    <<_:16/binary,Token:4/binary>> =
	crypto:sha(<<Key/binary, Chal:32/little, P/binary>>),
    ?debug("~p: make_token(~p, ~p, ~p) -> ~p~n", 
	   [?MODULE, P, Chal, Key, Token]),
    Token.

check_token_(Tok, P, Chal, Key) ->
    ?debug("check_token(~p, ~p, ~p, ~p)~n", [Tok, P, Chal, Key]),
    case crypto:sha(<<Key/binary, Chal:32/little, P/binary>>) of
	<<_:16/binary, Tok:4/binary>> ->
	    ?debug("check_token: true (~p)~n", [Tok]),
	    true;
	<<_:16/binary, WrongTok:4/binary>> ->
	    ?debug("check_token: false(~p)~n", [ WrongTok]),
	    false
    end.

recv(S) ->
    {TData,TClosed,TError} = exo_socket:tags(S),
    Socket = exo_socket:socket(S),
    case exo_socket:getopts(S, [active]) of
	{ok, [{active,false}]} ->
	    exo_socket:setopts(S, [{active,once}]);
	{ok, _} ->
	    ok
    end,
    receive
	{TClosed, Socket} -> error(closed);
	{TError, Socket, Reason} -> error({TError, Reason});
	{TData, Socket, Data} ->
	    Data
    after ?TIMEOUT ->
	    error(timeout)
    end.

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
%%%    BERT rpc client
%%% @end
%%% Created : 14 Dec 2011 by Tony Rogvall <tony@rogvall.se>

-module(nice_bert_rpc).

-include("bert.hrl").

-comile(export_all).
-export([call_host/3, call_host/4, call_host/6]).
-export([cast_host/3, cast_host/4, cast_host/6]).
-export([callback_host/5, callback_host/6, callback_host/8]).
-export([call/4, cast/4, info/3]).
-export([open/0, open/1, open/2, open/4]).
-export([disconnect/3, close/1, read_chunk/1]).

-type call_result() :: 
	{reply,Result::term(),CacheInfo::cache_info()} |
	{stream,Socket::socket(),CacheInfo::cache_info()} |
	{error,Reason::term()}.

-type cast_result() :: 
	noreply |
	{stream,Socket::socket(),CacheInfo::cache_info()} |
	{error,Reason::term()}.

-type socket() :: port().

-type cache_info() :: list(term()).

-type protocol() :: tcp | ssl | probe_ssl | http.


-define(CONNECT_TIMEOUT, 5000).

-define(dbg(F,A), io:format((F),(A))).


%%% @doc
%%%    Call local host on BERT "standard port" 9999
%%% @end
-spec call_host(Mod::atom(), Fun::atom(), Args::[term()]) -> 
		       call_result().

call_host(Mod, Fun, Args) ->
    call_host("localhost", ?BERT_PORT, [tcp], Mod, Fun, Args).

-spec call_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()]) ->
		       call_result().

call_host(Host, Mod, Fun, Args) ->
    call_host(Host, ?BERT_PORT, [tcp], Mod, Fun, Args).

-spec call_host(Host::string(), Port::integer(1..65535),
		Protos::[protocol()],
		Mod::atom(), Fun::atom(), Args::[term()]) ->
		       call_result().    
call_host(Host, Port, Protos, Mod, Fun, Args)
  when is_atom(Mod), is_atom(Fun), is_list(Args) ->
    case open(Host, Port, Protos, ?CONNECT_TIMEOUT) of
	{ok, Pid} when is_pid(Pid) ->
	    call(Pid, Mod, Fun, Args);
	{ok, Socket} ->
	    case call(Socket, Mod, Fun, Args) of
		Stream = {stream,_Socket,_CacheInfo} ->
		    Stream;
		Result ->
		    close(Socket),
		    Result
	    end;
	{error, _} = Error ->
	    Error
    end.

%%% @doc
%%%    Cast MFA to local host on BERT "standard port" 9999
%%% @end

-spec cast_host(Mod::atom(), Fun::atom(), Args::[term()]) -> 
		       cast_result().
cast_host(Mod, Fun, Args) ->
    cast_host("localhost", ?BERT_PORT, [tcp], Mod, Fun, Args).

-spec cast_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()]) ->
		       cast_result().

cast_host(Host, Mod, Fun, Args) ->
    cast_host(Host, ?BERT_PORT, [tcp], Mod, Fun, Args).

-spec cast_host(Host::string(), Port::integer(1..65535),
		Protos::[protocol()],
		Mod::atom(), Fun::atom(), Args::[term()]) ->
		       cast_result().    

cast_host(Host, Port, Protos, Mod, Fun, Args) 
  when is_list(Protos),
       is_atom(Mod), is_atom(Fun), is_list(Args) ->
    {ok,Socket} = open(Host, Port, Protos, ?CONNECT_TIMEOUT),
    Result = cast(Socket, Mod, Fun, Args),
    if is_pid(Socket) ->
	    ok;
       true ->
	    close(Socket)
    end,
    Result.

%%% @doc
%%%    Callback cast to local host on BERT "standard port" 9999
%%% @end

-spec callback_host(Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Mod, Fun, Args, Service, MFA) ->
    callback_host("localhost", ?BERT_PORT, [tcp], Mod, Fun, Args, Service, MFA).

-spec callback_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Host, Mod, Fun, Args, Service, MFA) ->
    callback_host(Host, ?BERT_PORT, [tcp], Mod, Fun, Args, Service, MFA).

-spec callback_host(Host::string(), Port::integer(1..65535),
		    Protos::[protocol()],
		    Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Host, Port, Protos, Mod, Fun, Args, Service, MFA={M,F,A}) when
      is_list(Protos),
      is_atom(Mod), is_atom(Fun), is_list(Args),
      is_binary(Service),
      is_atom(M), is_atom(F), is_list(A) ->
    {ok,Socket} = open(Host, Port, Protos, ?CONNECT_TIMEOUT),
    Result = callback(Socket, Mod, Fun, Args, Service, MFA),
    close(Socket),
    Result.

%% send callback cast
callback(Socket, Mod, Fun, Args, Service, {M,F,A}) when
      is_atom(Mod), is_atom(Fun), is_list(Args),
      is_binary(Service),
      is_atom(M), is_atom(F), is_list(A) ->
    info(Socket, callback, [{service,Service},{mfa,M,F,A}]),
    cast(Socket, Mod, Fun, Args).

%%% @doc
%%%    Send info packet
%%% @end

info(XSocket, Command, Options) ->
    B = bert:to_binary({info,Command,Options}),
    exo_socket:send(XSocket, B).

%%% @doc
%%%    Send call packet
%%% @end

call(XSocket, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
				   is_list(Args);
				   is_binary(Mod), is_binary(Fun),
				   is_list(Args)->
    Req = {call,Mod,Fun,Args},
    if is_pid(XSocket) ->
	    {reply, gen_server:call(XSocket, {call, Req}, infinity), []};
       true ->
	    B = bert:to_binary(Req),
	    exo_socket:send(XSocket, B),
	    handle_result(XSocket, false, [])
    end.

%%% @doc
%%%    Send cast packet
%%% @end

cast(XSocket, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
				   is_list(Args);
				   is_binary(Mod), is_binary(Fun),
				   is_list(Args) ->
    Req = {cast,Mod,Fun,Args},
    if is_pid(XSocket) ->
	    case gen_server:call(XSocket, {cast, Req}) of
		{noreply} -> noreply;
		Other -> Other
	    end;
       true ->
	    B = bert:to_binary(Req),
	    exo_socket:send(XSocket, B),
	    handle_result(XSocket, false, [])
    end.

handle_result(XSocket, Stream, CacheInfo) ->
    {Tag,Tag_closed,Tag_error} = exo_socket:tags(XSocket),
    Socket = exo_socket:socket(XSocket),
    receive
	{Tag, Socket, Data0} ->
	    Data = exo_socket:auth_incoming(XSocket, Data0),
	    case bert:to_term(Data) of
		{info, stream, []} ->
		    exo_socket:setopts(XSocket, [{active, once}]),
		    handle_result(XSocket, true, CacheInfo);
		{info, cache, CacheInfo1} ->
		    exo_socket:setopts(XSocket, [{active, once}]),
		    handle_result(XSocket, Stream, CacheInfo++CacheInfo1);
		{noreply} ->  %% async request return 
		    noreply;
		{reply, []} when Stream ->
		    {stream,XSocket,CacheInfo};
		{reply, Result} ->
		    {reply, Result, CacheInfo};
		Error = {error, _Err} ->
		    Error
	    end;
	{Tag_closed, Socket} ->
	    {error, closed};
	{Tag_error, Socket, Reason} ->
	    {error, Reason}
    end.

%%% @doc
%%%    Read a streamed block of data
%%% @end

read_chunk(XSocket) ->
    {Tag,Tag_closed,Tag_error} = exo_socket:tags(XSocket),
    Socket = exo_socket:socket(XSocket),
    exo_socket:setopts(XSocket, [{active, once}]),
    receive
	{Tag, Socket, <<>>} ->
	    end_of_stream;
	{Tag, Socket, Data} ->
	    {ok, Data};
	{Tag_closed, Socket} ->
	    {error, closed};
	{Tag_error, Socket, Reason} ->
	    {error, Reason}
    end.

%%% @doc
%%%    Open a transport connection
%%% @end

open() ->
    open("localhost", ?BERT_PORT).

open(Host) ->
    open(Host, ?BERT_PORT).

open(IP, Port) ->
    open(IP, Port, [tcp], ?CONNECT_TIMEOUT).

open(IP, Port, Protos, Timeout) ->
    AuthOptions = bert_rpc:auth_options(),
    SSLOptions = [{verify, verify_none}],
    Opts = [binary, {packet,4}, {active,once}] ++ SSLOptions ++ AuthOptions,
    bert_rpc_exec:get_session(IP, Port, Protos, Opts, Timeout).
%%%
%%% @doc
%%%    Close a transport connection
%%% @end

disconnect(Host, Port, Protos) ->
    case bert_rpc_exec:get_session(Host, Port, Protos, [{auto_connect, false}],
				   ?CONNECT_TIMEOUT) of
	{error, no_connection} ->
	    ok;
	{ok, Pid} ->
	    gen_server:call(Pid, close)
    end.

close(XSocket) ->
    exo_socket:close(XSocket).

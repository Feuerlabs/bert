%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%    BERT rpc client
%%% @end
%%% Created : 14 Dec 2011 by Tony Rogvall <tony@rogvall.se>

-module(bert_rpc).

-include("bert.hrl").

-comile(export_all).
-export([call_host/3, call_host/4, call_host/5]).
-export([cast_host/3, cast_host/4, cast_host/5]).
-export([callback_host/5, callback_host/6, callback_host/7]).
-export([call/4, cast/4, info/3]).
-export([open/0, open/1, open/2, close/1, read/1]).

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


%%% @doc
%%%    Call local host on BERT "standard port" 9999
%%% @end
-spec call_host(Mod::atom(), Fun::atom(), Args::[term()]) -> 
		       call_result().

call_host(Mod, Fun, Args) ->
    call_host("localhost", Mod, Fun, Args).

-spec call_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()]) ->
		       call_result().

call_host(Host, Mod, Fun, Args) ->
    call_host(Host, ?BERT_PORT, Mod, Fun, Args).

-spec call_host(Host::string(), Port::integer(1..65535),
		Mod::atom(), Fun::atom(), Args::[term()]) ->
		       call_result().    
call_host(Host, Port, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
					   is_list(Args) ->
    {ok,Socket} = open(Host, Port),
    case call(Socket, Mod, Fun, Args) of
	Stream = {stream,_Socket,_CacheInfo} ->
	    Stream;
	Result ->
	    close(Socket),
	    Result
    end.

%%% @doc
%%%    Cast MFA to local host on BERT "standard port" 9999
%%% @end

-spec cast_host(Mod::atom(), Fun::atom(), Args::[term()]) -> 
		       cast_result().
cast_host(Mod, Fun, Args) ->
    cast_host("localhost", Mod, Fun, Args).

-spec cast_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()]) ->
		       cast_result().

cast_host(Host, Mod, Fun, Args) ->
    cast_host(Host, ?BERT_PORT, Mod, Fun, Args).

-spec cast_host(Host::string(), Port::integer(1..65535),
		Mod::atom(), Fun::atom(), Args::[term()]) ->
		       cast_result().    

cast_host(Host, Port, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
					   is_list(Args) ->
    {ok,Socket} = open(Host, Port),
    Result = cast(Socket, Mod, Fun, Args),
    close(Socket),
    Result.

%%% @doc
%%%    Callback cast to local host on BERT "standard port" 9999
%%% @end

-spec callback_host(Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Mod, Fun, Args, Service, MFA) ->
    callback_host("localhost", Mod, Fun, Args, Service, MFA).

-spec callback_host(Host::string(), Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Host, Mod, Fun, Args, Service, MFA) ->
    callback_host(Host, ?BERT_PORT, Mod, Fun, Args, Service, MFA).

-spec callback_host(Host::string(), Port::integer(1..65535),
		    Mod::atom(), Fun::atom(), Args::[term()],
		    Service::binary(), 
		    MFA::{M::atom(),F::atom(),A::[term()]}) ->
			   cast_result().

callback_host(Host, Port, Mod, Fun, Args, Service, MFA={M,F,A}) when
      is_atom(Mod), is_atom(Fun), is_list(Args),
      is_binary(Service),
      is_atom(M), is_atom(F), is_list(A) ->
    {ok,Socket} = open(Host, Port),
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

info(Socket, Command, Options) ->
    B = bert:to_binary({info,Command,Options}),
    gen_tcp:send(Socket, B).

%%% @doc
%%%    Send call packet
%%% @end

call(Socket, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
				  is_list(Args) ->
    B = bert:to_binary({call,Mod,Fun,Args}),
    gen_tcp:send(Socket, B),
    handle_result(Socket, false, []).

%%% @doc
%%%    Send cast packet
%%% @end

cast(Socket, Mod, Fun, Args) when is_atom(Mod), is_atom(Fun), 
				  is_list(Args) ->
    B = bert:to_binary({cast,Mod,Fun,Args}),
    gen_tcp:send(Socket, B),
    handle_result(Socket, false, []).


handle_result(Socket, Stream, CacheInfo) ->
    receive
	{tcp, Socket, Data} ->
	    case bert:to_term(Data) of
		{info, stream, []} ->
		    inet:setopts(Socket, {actice, once}),
		    handle_result(Socket, true, CacheInfo);
		{info, cache, CacheInfo1} ->
		    inet:setopts(Socket, {actice, once}),
		    handle_result(Socket, Stream, CacheInfo1);
		{noreply} ->  %% async request return 
		    noreply;
		{reply, []} when Stream ->
		    {stream,Socket,CacheInfo};
		{reply, Result} ->
		    {reply, Result, CacheInfo};
		Error = {error, _Err} ->
		    Error
	    end;
	{tcp_closed, Socket} ->
	    {error, closed};
	{tcp_error, Socket, Reason} ->
	    {error, Reason}
    end.

%%% @doc
%%%    Read a streamed block of data
%%% @end

read(Socket) ->
    inet:setopts(Socket, {actice, once}),
    receive
	{tcp, Socket, <<>>} ->
	    end_of_stream;
	{tcp, Socket, Data} ->
	    {ok, Data};
	{tcp_closed, Socket} ->
	    {error, closed};
	{tcp_error, Socket, Reason} ->
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
    gen_tcp:connect(IP, Port, [binary, {packet,4}, {active,once}]).

%%% @doc
%%%    Close a transport connection
%%% @end

close(Socket) ->
    gen_tcp:close(Socket).

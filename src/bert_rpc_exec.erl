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
%%%    BERT-RPC
%%% @end
%%% Created : 17 Sep 2011 by Tony Rogvall <tony@rogvall.se>

-module(bert_rpc_exec).

-behaviour(exo_socket_server).

-include("bert.hrl").
-include_lib("lager/include/log.hrl").

-define(dbg(F,A), ?debug("~p " ++ F, [self()|A])).
%%
%% FIXME:
%%  support for ssl transport
%%  optional support for authentication
%%  optional support for ssl upgrade
%%
%%  access list elements
-type access_mfa() :: atom() | mfa().
-type access_element() :: {access_mfa(),cache_options()}.  % FIXME: update
-type validation() :: binary().
-type cache_options() :: {validation,validation()} |
			 {expiration,non_neg_integer()} |
			 {access,public} |
			 {access, private}.

%%
-record(state,
	{
	  stream = false,
	  cache = [],
	  callback = [],
	  access = []   :: [access_element()],
	  remote_access = [] :: [access_element()]
	}).

-export([init/2, data/3, close/2, error/3]).

-export([start_link/1]).
-export([start/0, start/2, start/3]).
-export([start_ssl/0, start_ssl/2, start_ssl/3]).
-export([get_session/5]).
-export([reuse_init/2, reuse_options/4,
	 received_reuse_info/2, handle_call/3]).

%%-define(dbg(F,A), io:format((F),(A))).

start() ->
    start(?BERT_PORT,[]).

start(Port, Options) ->
    start(Port, Options, []).

start(Port, Options, ExoOptions) ->
    do_start(Port, Options, ExoOptions, start).

start_link(Port, Options, ExoOptions) ->
    do_start(Port, Options, ExoOptions, start_link).

do_start(Port, Options, ExoOptions, StartF) when StartF==start;
						 StartF==start_link ->
    case lists:keymember(ssl, 1, Options) of
	{_, true} ->
	    start_ssl(Port, Options, ExoOptions);
	_ ->
	    exo_socket_server:StartF(Port,[tcp],
				     [{active,once},{packet,4},binary,
				      {reuseaddr,true} | ExoOptions],
				     ?MODULE, Options)
    end.

start_link(Options) ->
    case lists:keyfind(port, 1, Options) of
	false ->
	    erlang:error(unknown_port);
	{_, Port} ->
	    Exo = proplists:get_value(exo, Options, []),
	    case lists:keyfind(ssl, 1, Options) of
		{_, true} ->
		    start_link_ssl(Port, Options, Exo);
		_ ->
		    start_link(Port, Options, Exo)
	    end
    end.

start_ssl() ->
    start_ssl(?BERT_PORT,[]).

start_ssl(Port, Options) ->
    start_ssl(Port, Options, []).

start_ssl(Port, Options, ExoOptions) ->
    do_start_ssl(Port, Options, ExoOptions, start).

start_link_ssl(Port, Options, ExoOptions) ->
    do_start_ssl(Port, Options, ExoOptions, start_link).

do_start_ssl(Port, Options, ExoOptions, StartF) when
      StartF == start; StartF == start_link ->
    Dir = code:priv_dir(bert),
    exo_socket_server:StartF(Port,[tcp,probe_ssl],
			     [{active,once},{packet,4},binary,
			      {debug, true},
			      {verify, verify_none}, %% no client cert required
			      %% server demo - cert
			      {keyfile, filename:join(Dir, "host.key")},
			      {certfile, filename:join(Dir, "host.cert")},
			      {reuseaddr,true} | ExoOptions], ?MODULE, Options).


get_session(IP, Port, Protos, Opts, Timeout) ->
    case whereis(?MODULE) of
	undefined ->
	    maybe_connect(IP, Port, Protos, Opts, Timeout);
	_ ->
	    case gen_server:call(
		   ?MODULE, {get_session, IP, Port, [Protos, Opts, Timeout]}) of
		connect ->
		    maybe_connect(IP, Port, Protos, Opts, Timeout);
		rejected ->
		    {error, no_connection};
		Pid when is_pid(Pid) ->
		    {ok, Pid}
	    end
    end.

maybe_connect(IP, Port, Protos, Opts, Timeout) ->
    case proplists:get_bool(auto_connect, Opts, true) of
	true ->
	    exo_socket:connect(IP, Port, Protos, Opts, Timeout);
	false ->
	    {error, no_connection}
    end.

reuse_init(_, _) ->
    register(?MODULE, self()),
    {ok, []}.

reuse_options(_Host, _Port, Args, _St) ->
    ?debug("reuse_options(Args = ~p)~n", [Args]),
    case proplists:get_value(access, Args, []) of
	[] ->
	    [];
	[_|_] = Access ->
	    [{bert_enc, access, Access}]
    end.

received_reuse_info(Info, State) ->
    case lists:keyfind(access, 1, Info) of
	{_, Access} ->
	    {ok, State#state{remote_access = Access}};
	false ->
	    {ok, State}
    end.

init(Socket, Options) ->
    {ok,{IP,Port}} = exo_socket:peername(Socket),
    ?dbg("bert_rpc_exec: connection from: ~p : ~p\n", [IP, Port]),
    Access = proplists:get_value(access, Options, []),
    {ok, #state{ access=Access}}.

data(Socket, Data, State) ->
    try bert:to_term(Data) of
	Request ->
	    ?dbg("bert_rpc_exec: request: ~w\n", [Request]),
	    handle_request(Socket, Request, State)
    catch
	error:_Error ->
	    B = {error,{protcol,?PROT_ERR_UNDESIGNATED,<<"BERTError">>,
			%% detail
			<<"unable to decode">>,
			%% backtrace?
			[]}},
	    exo_socket:send(Socket, bert:to_binary(B)),
	    {ok,State}
    end.

handle_call(_, get_access, #state{access = A} = State) ->
    {reply, A, State};
handle_call(_, {set_access, A}, State) ->
    %% should perhaps check that it's a valid access list... FIXME
    {reply, ok, State#state{access = A}};
handle_call(C, {C, _M,_F,_A} = Req, #state{} = St) ->
    ?dbg("handle_call(~p)~n", [Req]),
    {send, bert:to_binary(Req), St}.


%% handle_call(C, {C, M,F,A} = Req, #state{remote_access = Access} = St) ->
%%     ?dbg("handle_call(~p, Access=~p)~n", [Req, Access]),
%%     if Access == [] ->
%% 	    {send, bert:to_binary(Req), St};
%%        true ->
%% 	    case access_test(M,F,length(A), Access, false) of
%% 		{ok, {_M1,_F1,_A1}, _Conv} ->
%% 		    %% We now know that there is a pattern. Let the remote side
%% 		    %% do the conversion.
%% 		    {send, bert:to_binary(Req), St};
%% 			     %% {C, M1,F1, convert_args(Conv,A)}),St};
%% 		{error,ServerCode,Detail} ->
%% 		    Msg = server_error_msg(ServerCode, Detail, []),
%% 		    if C==call ->
%% 			    {reply, Msg, St};
%% 		       C==cast ->
%% 			    {ignore, St}
%% 		    end
%% 	    end
%%     end.


%%
%% close - retrive statistics
%% transport socket SHOULD still be open, but ssl may not handle this!
%%
close(Socket, State) ->
    case exo_socket:getstat(Socket, exo_socket:stats()) of
	{ok,_Stats} ->
	    ?dbg("bert_rpc_exec: close, stats=~w\n", [_Stats]),
	    {ok, State};
	{error,_Reason} ->
	    ?dbg("bert_rpc_exec: close, stats error=~w\n", [_Reason]),
	    {ok, State}
    end.

error(_Socket,Error,State) ->
    ?dbg("bert_rpc_exec: error = ~p\n", [Error]),
    {stop, Error, State}.

%%
%% Internal
%%
handle_request(Socket, Request, State) ->
    io:fwrite(user, "handle_request(Socket, ~p, State)~n", [Request]),
    case Request of
	{call,Module,Function,Arguments} when is_atom(Module),
					      is_atom(Function),
					      is_list(Arguments) ->
	    ?dbg("Request = ~p~n", [{call,Module,Function,Arguments}]),
	    case access_test(Module,Function,length(Arguments),
			     State#state.access) of
		{ok, {M, F, _A}, Conv} = _AccessRes ->
		    ?dbg("access_test() -> ~p~n", [_AccessRes]),
		    %% handle security  + stream input ! + stream output
		    NewArgs = convert_args(Conv, Arguments),
		    try apply_f(M, F, NewArgs) of
			Result ->
			    B = {reply,Result},
			    try bert:to_binary(B) of
				Bin ->
				    exo_socket:send(Socket, Bin),
				    {ok,reset_state(State)}
			    catch
				error:Error ->
				    Trace = erlang:get_stacktrace(),
				    Detail = list_to_binary(io_lib:format("~p",[Error])),
				    send_server_error(Socket, 2, Detail, Trace),
				    {ok,reset_state(State)}
			    end
		    catch
			error:Error ->
			    Trace = erlang:get_stacktrace(),
			    Detail = list_to_binary(io_lib:format("~p",[Error])),
			    send_server_error(Socket, 2, Detail, Trace),
			    {ok,reset_state(State)}
		    end;
		{error,ServerCode,Detail} = _AccessErr ->
		    ?dbg("access_test() -> ~p~n", [_AccessErr]),
		    send_server_error(Socket, ServerCode, Detail, []),
		    {ok,reset_state(State)}
	    end;

	{cast,Module,Function,Arguments} when is_atom(Module),
					      is_atom(Function),
					      is_list(Arguments) ->
	    case access_test(Module,Function,length(Arguments),State) of
		ok ->
		    B = {noreply},
		    exo_socket:send(Socket, bert:to_binary(B)),
		    try apply(Module,Function,Arguments) of
			Value ->
			    callback(Value, State)
		    catch
			error:_ ->
			    {ok,reset_state(State)}
		    end;
		{error,ServerCode,Detail} ->
		    send_server_error(Socket, ServerCode, Detail, []),
		    {ok,reset_state(State)}
	    end;

	{info, callback, Callback } ->
	    {ok, State#state { callback = Callback }};

	{info, cache, Options } ->
	    %% cases: [{validation,Token}]
	    {ok, State#state { cache = State#state.cache ++ Options }};

	{info, stream, []} ->
	    %% client will send call data as a stream
	    {ok, State#state { stream = true }};

	{noreply} ->
	    {reply, noreply, State};

	{reply, Reply} ->
	    {reply, Reply, State};

	{error,_} = Error ->
	    {reply, Error, State};

	_Other ->
	    send_server_error(Socket, ?SERV_ERR_UNDESIGNATED,
			      <<"protocol error">>, []),
	    {ok,State}
    end.

apply_f(M, F, A) ->
    apply(M, F, A).

convert_args(keep, As) -> As;
convert_args([H|T], Opts) when is_atom(H) ->
    case lists:keyfind(H, 1, Opts) of
	{_, V} -> [V | convert_args(T, Opts)];
	false  -> error({missing_argument, H})
    end;
convert_args([{opt,K,Default}|T], Opts) ->
    [proplists:get_value(K, Opts, Default) | convert_args(T, Opts)];
convert_args([{TypeConv, K}|T], Opts) ->
    case lists:keyfind(K, 1, Opts) of
	{_, V} -> [convert_type(TypeConv, V) | convert_args(T, Opts)];
	false  -> error({missing_argument, K})
    end;
convert_args([{TypeConv, K, Default}|T], Opts) ->
    case lists:keyfind(K, 1, Opts) of
	{_, V} -> [convert_type(TypeConv, V) | convert_args(T, Opts)];
	false  -> [Default | convert_args(T, Opts)]
    end;
convert_args([], _) ->
    [].

convert_type(TypeConv, V) ->
    case TypeConv of
	string_to_integer -> to_integer(V);
	string_to_float   ->
	    case erl_scan:string(V) of
		{ok, [{float, _, F}], _} -> F;
		_ -> error({bad_type, V})
	    end;
	string_to_atom -> to_atom(V);
	_ -> error({bad_type_converter, TypeConv})
    end.

to_integer(B) when is_binary(B) ->
    list_to_integer(binary_to_list(B));
to_integer(L) when is_list(L) ->
    list_to_integer(L);
to_integer(X) ->
    error({bad_type, X}).


to_atom(B) when is_binary(B) ->
    binary_to_atom(B, latin1);
to_atom(L) when is_list(L) ->
    list_to_atom(L);
to_atom(X) ->
    error({bad_type, X}).




reset_state(State) ->
    State#state { stream   = false,
		  cache    = [],
		  callback = [] }.

send_server_error(Socket, ServerCode, Detail, StackTrace) ->
    B = server_error_msg(ServerCode, Detail, StackTrace),
    exo_socket:send(Socket, bert:to_binary(B)).

server_error_msg(ServerCode, Detail, StackTrace) ->
    Trace = encode_stacktrace(StackTrace),
    {error,{server,ServerCode,<<"BERTError">>, Detail, Trace}}.

encode_stacktrace([{M,F,A}|Ts]) ->
    Arity = if is_integer(A) -> A;
	       is_list(A) -> length(A)
	    end,
    E = list_to_binary(io_lib:format("~w:~w/~w", [M,F,Arity])),
    [E | encode_stacktrace(Ts)];
encode_stacktrace([{M,F,A,L}|Ts]) ->
    Arity = if is_integer(A) -> A;
	       is_list(A) -> length(A)
	    end,
    File = proplists:get_value(file, L, "*"),
    Line = proplists:get_value(line, L, 0),
    E = list_to_binary(io_lib:format("~s:~w: ~w:~w/~w",
				     [File,Line,M,F,Arity])),
    [E | encode_stacktrace(Ts)];
encode_stacktrace([]) ->
    [].


callback(Value, State) ->
    case State#state.callback of
	[] ->
	    {ok,State};
	[{service,Service},{mfa,M,F,A}] ->
	    case string:tokens(binary_to_list(Service), ":") of
		[Host,PortString] ->
		    Port = list_to_integer(PortString),
		    catch bert_rpc:cast_host(Host,Port,[tcp], 
					     M, F, A ++ [Value]),
		    {ok, State#state { callback = []}};
		_Serv ->
		    ?dbg("callback bad service = ~p\n", [_Serv]),
		    {ok, State#state { callback = []}}
	    end
    end.

access_test(M,F,A, Access) ->
    access_test(M,F,A, Access, true).

access_test(M,F,A, Access,Check) ->
    if Access =:= [] ->  %% full access!!!
	    access_check(M,F,A,keep,Check);
       true ->
	    case check_list(Access, M, F, A) of
		false ->
		    {error, ?SERV_ERR_NO_SUCH_FUNCTION,
		     <<"access denied">>};
		{{M1, F1, A1}, Conv} ->
		    access_check(M1, F1, A1, Conv, Check)
	    end
    end.

check_list([{accept, M}|_], M, F, A) ->  {{M, F, A}, keep};
check_list([{accept, M, F, A}|_], M, F, A) -> {{M, F, A}, keep};
check_list([{reject, M}|_], M, _, _) -> false;
check_list([{reject, M, F, A}|_], M, F, A) -> false;
check_list([{propargs,M,F,Args}|_], M, F, 1) ->
    NewA = length(Args),
    {{M, F, NewA}, Args};
check_list([{verify, {Mv,Fv}}|T], M, F, A) ->
    case Mv:Fv(M, F, A) of
	continue -> check_list(T, M, F, A);
	{_,_,_} = MFA1 -> {MFA1, keep};
	{{_,_,_}, Conv} = Reply when is_list(Conv); Conv==keep -> Reply;
	false -> false
    end;
check_list([{redirect, [_|_] = Ms}|T], M, F, A) ->
    case lists:keyfind(M, 1, Ms) of
	{M, M1} ->
	    check_list(T, M1, F, A);
	false ->
	    case lists:keyfind({M,F,A}, 1, Ms) of
		false ->
		    check_list(T, M, F, A);
		{_, {_,_,_} = MFA1} ->
		    {MFA1, keep}
	    end
    end;
check_list([M|_], M, F, A)             -> {{M, F, A}, keep};
check_list([{M,F,A} = MFA|_], M, F, A) -> {MFA, keep};
check_list([_|T], M, F, A)             -> check_list(T, M, F, A);
check_list([], _, _, _)                -> false.


access_check(M,F,A, Conv, false) ->
    {ok, {M,F,A}, Conv};
access_check(M,F,A, Conv, true) ->
    case code:ensure_loaded(M) of
	false ->
	    {error, ?SERV_ERR_NO_SUCH_MODULE, <<"module not defined">>};
	{error,nofile} ->
	    {error, ?SERV_ERR_NO_SUCH_MODULE, <<"module not found">>};
	{module,M} ->
	    case erlang:function_exported(M,F,A) of
		false ->
		    case erlang:is_builtin(M,F,A) of
			true ->
			    {ok, {M,F,A}, Conv};
			false ->
			    {error, ?SERV_ERR_NO_SUCH_FUNCTION,
			     <<"function not defined">>}
		    end;
		true ->
		    {ok, {M,F,A}, Conv}
	    end
    end.

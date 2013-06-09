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

-define(SERVER, ?MODULE).

-define(dbg(F,A), ?debug("~p:~p: " ++ F, [?MODULE, self()|A])).

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

%% exo_socket_server callbacks
-export([init/2, 
	 data/3, 
	 close/2, 
	 error/3,
	 control/4]).

%% api
-export([start_link/1]).
-export([start/0, start/2, start/3]).
-export([start_ssl/0, start_ssl/2, start_ssl/3]).
-export([get_session/5]).
-export([reuse_init/2, 
	 reuse_options/4,
	 received_reuse_info/2]).
-export([request/2]). %% Used by exoport_gsms


%%%===================================================================
%%% API
%%%===================================================================
start() ->
    start(?BERT_PORT,[]).

start(Port, Options) ->
    start(Port, Options, []).

start(Port, Options, ExoOptions) ->
    do_start(Port, Options, ExoOptions, start).

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

%%--------------------------------------------------------------------
%% @doc
%% Sends 
%% @end
%%--------------------------------------------------------------------
-spec request(Request::term(), ReplyMethod::internal | external) ->
		     ok  | {error, Reason::term()}.
								       
request({C, _Mod, _Fun, _Args} = Request, external) 
when C == call;
     C == cast ->
    ?dbg("control: request ~p\n", [Request]),
    {ok, Access} = exoport:access(),
    case handle_call_and_cast(Request, Access) of
	{send, Result} ->
	    Result;
	{cast, {M, F, A}} ->
	    spawn(M, F, A),
	    ok;
	{error, {_Code, _Detail, _Trace}} = E ->
	    E;
	_Other ->
	    ?error("Unexpected result ~p of handle_call_and_cast(~p, ~p)",
		   [_Other, Request, Access])
    end;
    
request(Request, internal) ->
    case exo_socket_server:reusable_sessions(bert_rpc_exec) of
	[{{Host, Port}, Pid} | _Rest] ->
	    %% Send request to first available socket session
	    ?dbg("request: calling ~p:~p(~p) with ~p.", 
		 [Host, Port, Pid, Request]),
	    gen_server:call(Pid, {request, Request});
	_ ->
	    ?dbg("request: no connection.",  []),
	    {error, no_connection}
    end.

%%--------------------------------------------------------------------
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

%%--------------------------------------------------------------------
reuse_init(_, _) ->
    register(?MODULE, self()),
    {ok, []}.

%%--------------------------------------------------------------------
reuse_options(_Host, _Port, Args, _St) ->
    ?debug("reuse_options(Args = ~p)~n", [Args]),
    case proplists:get_value(access, Args, []) of
	[] ->
	    [];
	[_|_] = Access ->
	    [{bert_enc, access, Access}]
    end.

%%--------------------------------------------------------------------
received_reuse_info(Info, State) ->
    case lists:keyfind(access, 1, Info) of
	{_, Access} ->
	    {ok, State#state{remote_access = Access}};
	false ->
	    {ok, State}
    end.

%%%===================================================================
%%% exo_socket_server callbacks
%%%===================================================================
%%--------------------------------------------------------------------
init(Socket, Options) ->
    {ok,{IP,Port}} = exo_socket:peername(Socket),
    ?dbg("init: connection from: ~p : ~p\n", [IP, Port]),
    Access = proplists:get_value(access, Options, []),
    State = #state{access = Access},
    case proplists:get_value(idle_timeout, Options) of
	undefined -> {ok, State};
	T when is_integer(T) -> {ok, State, T}
    end.

data(Socket, Data, State) when is_binary(Data) ->
    try bert:to_term(Data) of
	Request ->
	    ?dbg("data: request: ~w\n", [Request]),
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
    end;
data(Socket, Request, State) ->
    %% Already converted to bert format
    ?dbg("data: request: ~w\n", [Request]),
    handle_request(Socket, Request, State).


%%--------------------------------------------------------------------
%% @doc
%%
%% Calls relayed from exo_socket_session:handle_call/3.
%% @end
%%--------------------------------------------------------------------
-spec control(Socket::term(), 
	      Request::term(), 
	      From::term(), 
	      State::#state{}) ->
		     {reply, Reply::term(),State::#state{}} |
		     {noreply, State::#state{}} |
		     {ignore, State::#state{}} |
		     {data, Data::term(), State::#state{}} | 
		     {send, Bin::binary(), State::#state{}} |
		     {stop, Reason::term(),State::#state{}}.

control(_Socket, {request, Request} = Call, _From, State) ->
    ?dbg("control: call ~p\n", [Call]),
    %% Transfer to data callback for reply on socket
    {data, Request, State};

control(_Socket, get_access, _From, #state{access = A} = State) ->
    {reply, A, State};
control(_Socket, {set_access,  A}, _From, State) ->
    %% should perhaps check that it's a valid access list... FIXME
    {reply, ok, State#state{access = A}};
control(_Socket, {C, _M,_F,_A} = Req, _From, #state{} = St) 
  when C == call;
       C == cast ->
    ?dbg("control(~p)~n", [Req]),
    {send, bert:to_binary(Req), St}.

%%--------------------------------------------------------------------
%% @doc
%%
%% close - retrive statistics
%% transport socket SHOULD still be open, but ssl may not handle this!
%%
%% @end
%%--------------------------------------------------------------------
close(Socket, State) ->
    case exo_socket:getstat(Socket, exo_socket:stats()) of
	{ok,_Stats} ->
	    ?dbg("close: stats=~w\n", [_Stats]),
	    {ok, State};
	{error,_Reason} ->
	    ?dbg("close: stats error=~w\n", [_Reason]),
	    {ok, State}
    end.

error(_Socket,Error,State) ->
    ?dbg("error: ~p\n", [Error]),
    {stop, Error, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
start_link(Port, Options, ExoOptions) ->
    do_start(Port, Options, ExoOptions, start_link).

do_start(Port, Options, ExoOptions, StartF) when StartF==start;
						 StartF==start_link ->
    case lists:keymember(ssl, 1, Options) of
	{_, true} ->
	    start_ssl(Port, Options, ExoOptions);
	_ ->
	    exo_socket_server:StartF(Port, [tcp], 
				     [{active,once},{packet,4},binary,
				      {reuseaddr,true} |
				      send_timeout_opt(ExoOptions)],
				     ?MODULE, Options)
    end.

start_link_ssl(Port, Options, ExoOptions) ->
    do_start_ssl(Port, Options, ExoOptions, start_link).

do_start_ssl(Port, Options, ExoOptions, StartF) when
      StartF == start; StartF == start_link ->
    Dir = code:priv_dir(bert),
    exo_socket_server:StartF(Port, [tcp,probe_ssl],
			     [{active,once},{packet,4},binary,
			      {debug, true},
			      {verify, verify_none}, %% no client cert required
			      %% server demo - cert
			      {keyfile, filename:join(Dir, "host.key")},
			      {certfile, filename:join(Dir, "host.cert")},
			      {reuseaddr,true} | ExoOptions], ?MODULE, Options).


send_timeout_opt(Opts) ->
    Opts1 = case lists:keymember(send_timeout, 1, Opts) of
		true ->
		    [{send_timeout, 30}|Opts];
		false ->
		    Opts
	    end,
    lists:keystore(send_timeout_close, 1, Opts1, {send_timeout_close, true}).

maybe_connect(IP, Port, Protos, Opts, Timeout) ->
    case proplists:get_value(auto_connect, Opts, true) of
	true ->
	    exo_socket:connect(IP, Port, Protos, Opts, Timeout);
	false ->
	    {error, no_connection}
    end.

handle_request(Socket, Request, State) ->
    ?dbg("handle_request: Socket ~p, Request ~p, State ~p~n", 
	 [Socket, Request, State]),
    case handle_request(Request, State) of
	{send, Result} ->
	    exo_socket:send(Socket, Result),
	    {ok, reset_state(State)};
	{cast, {M, F, A}} ->
	    %% Transformed MFA
	    exo_socket:send(Socket, bert:to_binary({noreply})),
	    try apply(M, F, A) of
		Value ->
		    callback(Value, State)
	    catch
		error:_ ->
		    {ok, reset_state(State)}
	    end;
	{ok, NewState} ->
	    {ok, NewState};
	{error, {Code, Detail, Trace}} ->
	    send_server_error(Socket, Code, Detail, Trace),
	    {ok, reset_state(State)};
	Other ->
	    %% Transparant
	    Other
    end.
	
 

handle_request({C,Module,Function,Arguments}, State) 
  when C == call; 
       C == cast->
    handle_call_and_cast({C,Module,Function,Arguments}, 
			 State#state.access);
handle_request({info, callback, Callback}, State) ->
    {ok, State#state { callback = Callback }};
handle_request({info, cache, Options}, State) ->
    %% cases: [{validation,Token}]
    {ok, State#state { cache = State#state.cache ++ Options }};
handle_request({info, stream, []}, State) ->
    %% client will send call data as a stream
    {ok, State#state { stream = true }};
handle_request({noreply}, State) ->
    {noreply, State};
handle_request({reply, Reply}, State) ->
    {reply, Reply, State};
handle_request({error,_} = Error, State) ->
    {reply, Error, State};
handle_request(close, State) ->
    {stop, closed, State};
handle_request(_Other, _State) ->
    {error, {?SERV_ERR_UNDESIGNATED, <<"protocol error">>, []}}.

handle_call_and_cast({C,Module,Function,Arguments}, Access) ->
    ?dbg("handle_request: ~p~n", [{call,Module,Function,Arguments}]),
    case {C, access_test({Module,Function,Arguments}, Access)} of
	{call, {ok, {M, F, A}}} ->
	    %% Execute first
	    try apply1(M, F, A) of
		{ok, Result} ->
		    ?dbg("result: ~p\n", [Result]),
		    {send, Result}
	    catch
		error:_Error ->
		    Trace = erlang:get_stacktrace(),
		    Detail = list_to_binary(io_lib:format("~p",[_Error])),
		    ?dbg("handle_request: crash ~s ~p\n", [Detail,Trace]),
		    {error, {2, Detail, Trace}}
	    end;
	{cast, {ok, {M, F, A}}} ->
	    %% Reply first
	    {cast, {M, F, A}};
	{_C, {error,ServerCode,Detail}} ->
	    {error, {ServerCode,Detail, []}}
    end.


apply1(M, F, A) ->
    Result = apply(M, F, A),
    ?dbg("result: ~p\n", [Result]),
    Reply = {reply, Result},
    Bin =  bert:to_binary(Reply),
    {ok, Bin}.


convert_args(keep, As) -> As;
convert_args([H|T], Opts) when is_atom(H) ->
    case lists:keyfind(H, 1, Opts) of
	{_, V} -> [V | convert_args(T, Opts)];
	false  -> error({missing_argument, H})
    end;
convert_args([{args,Args}|T], [Opts|Opts1]) ->
    convert_args(Args, Opts) ++ convert_args(T, Opts1);
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
	    case erl_scan:string(to_list(V)) of
		{ok, [{float, _, F}], _} -> F;
		_ -> error({bad_type, V})
	    end;
	string_to_atom -> to_atom(V);
	_ -> error({bad_type_converter, TypeConv})
    end.

to_list(B) when is_binary(B) ->
    binary_to_list(B);
to_list(L) when is_list(L) ->
    L.

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
to_atom(A) when is_atom(A) ->
    A;
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

access_test({Module0,Function0,Arguments}, Access) 
  when is_list(Arguments), is_binary(Module0), is_binary(Function0) ->
    Module = to_atom(Module0),
    Function = to_atom(Function0),
    access_test({Module,Function,Arguments}, Access);
access_test({Module,Function,Arguments}, Access) 
  when is_list(Arguments), is_atom(Module), is_atom(Function) ->
    ?dbg("handle_request: ~p~n", [{call,Module,Function,Arguments}]),
    case access_test(Module,Function,length(Arguments),Access) of
	{ok, {M, F, _A}, Conv} = _AccessRes ->
	    ?dbg("access_test() -> ~p~n", [_AccessRes]),
	    %% handle security  + stream input ! + stream output
	    NewArgs = convert_args(Conv, Arguments),
	    ?dbg(": ~s:~s args=~p\n", [M,F,NewArgs]),
	    {ok, {M, F, NewArgs}};
	{error,_ServerCode,_Detail} = AccessErr ->
	    AccessErr
    end;
access_test(_Other, _State) ->
    ok.


access_test(M,F,A, Access) ->
    access_test(M,F,A, Access, true).

access_test(M,F,A, [] = Access,Check) ->
    ?dbg("access_test(~p,~p,~p,~p,~p) - full access", [M,F,A,Access,Check]),
    access_check(M,F,A,keep,Check);
access_test(M,F,A, Access,Check) ->
    ?dbg("access_test(~p,~p,~p,~p,~p)~n", [M,F,A,Access,Check]),
    case check_list(Access, M, F, A) of
	false ->
	    {error, ?SERV_ERR_NO_SUCH_FUNCTION,<<"access denied">>};
	{{M1, F1, A1}, Conv} = Res ->
	    ?dbg("check_list() -> ~p~n", [Res]),
	    access_check(M1, F1, A1, Conv, Check)
    end.

check_list(Access=[_Check|_], M, F, A) ->
    ?debug("check_list: ~p [~p,~p,~p]", [_Check, M, F, A]),
    check_list_(Access, M, F, A);
check_list([], _M,_F,_A) ->
    false.


check_list_([{accept, M}|_], M, F, A) ->  {{M, F, A}, keep};
check_list_([{accept, M, F, A}|_], M, F, A) -> {{M, F, A}, keep};
check_list_([{reject, M}|_], M, _, _) -> false;
check_list_([{reject, M, F, A}|_], M, F, A) -> false;
check_list_([{propargs,M,F,Args}|_], M, F, 1) ->
    NewA = length(Args),
    {{M, F, NewA}, Args};
check_list_([{verify, {Mv,Fv}}|T], M, F, A) ->
    case Mv:Fv(M, F, A) of
	continue -> check_list(T, M, F, A);
	{_,_,_} = MFA1 -> {MFA1, keep};
	{{_,_,_}, Conv} = Reply when is_list(Conv); Conv==keep -> Reply;
	false -> false
    end;
check_list_([{redirect, [_|_] = Ms}|T], M, F, A) ->
    case lists:keyfind(M, 1, Ms) of
	{M, M1} ->
	    check_list(T, M1, F, A);
	_ ->
	    case lists:keyfind({M,F,A}, 1, Ms) of
		false ->
		    check_list(T, M, F, A);
		{_, {M1,F1,A1} = _MFA1} ->
		    check_list(T,M1,F1,A1)
		     %% {MFA1, keep}
	    end
    end;
check_list_([M|_], M, F, A)             -> {{M, F, A}, keep};
check_list_([{M,F,A} = MFA|_], M, F, A) -> {MFA, keep};
check_list_([_|T], M, F, A)             -> check_list(T, M, F, A);
check_list_([], _, _, _)                -> false.


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

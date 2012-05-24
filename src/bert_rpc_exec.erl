%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%    BERT-RPC
%%% @end
%%% Created : 17 Sep 2011 by Tony Rogvall <tony@rogvall.se>

-module(bert_rpc_exec).

-behaviour(exo_socket_server).

-include("bert.hrl").
-include_lib("lager/include/log.hrl").
%%
%% FIXME:
%%  support for ssl transport
%%  optional support for authentication
%%  optional support for ssl upgrade
%%
%%  access list elements
-type access_mfa() :: atom() | mfa().
-type access_element() :: {access_mfa(),cache_options()}.
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
	  access = []   :: [access_element()]
	}).

-export([init/2, data/3, close/2, error/3]).

-export([start_link/1]).
-export([start/0, start/2, start/3]).
-export([start_ssl/0, start_ssl/2, start_ssl/3]).
-export([get_session/5]).
-export([reuse_init/2]).

-define(dbg(F,A), io:format((F),(A))).

start() ->
    start(?BERT_PORT,[]).

start(Port, Options) ->
    start(Port, Options, []).

start(Port, Options, ExoOptions) ->
    case lists:keymember(ssl, 1, Options) of
	{_, true} ->
	    start_ssl(Port, Options);
	_ ->
	    exo_socket_server:start(Port,[tcp],
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
		    start_ssl(Port, Options, Exo);
		_ ->
		    start(Port, Options, Exo)
	    end
    end.

start_ssl() ->
    start_ssl(?BERT_PORT,[]).

start_ssl(Port, Options) ->
    start_ssl(Port, Options, []).

start_ssl(Port, Options, ExoOptions) ->
    Dir = code:priv_dir(bert),
    exo_socket_server:start(Port,[tcp,probe_ssl],
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
	    exo_socket:connect(IP, Port, Protos, Opts, Timeout);
	_ ->
	    case gen_server:call(
		   ?MODULE, {get_session, IP, Port, [Protos, Opts, Timeout]}) of
		connect ->
		    exo_socket:connect(IP, Port, Protos, Opts, Timeout);
		rejected ->
		    {error, no_connection};
		Pid when is_pid(Pid) ->
		    {ok, Pid}
	    end
    end.

reuse_init(_, _) ->
    register(?MODULE, self()),
    {ok, []}.

init(Socket, Options) ->
    {ok,{IP,Port}} = exo_socket:peername(Socket),
    ?debug("bert_rpc_exec: connection from: ~p : ~p\n", [IP, Port]),
    Access = proplists:get_value(access, Options, []),
    {ok, #state{ access=Access}}.

data(Socket, Data, State) ->
    try bert:to_term(Data) of
	Request ->
	    ?debug("bert_rpc_exec: request: ~w\n", [Request]),
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
%%
%% close - retrive statistics
%% transport socket SHOULD still be open, but ssl may not handle this!
%%
close(Socket, State) ->
    case exo_socket:getstat(Socket, exo_socket:stats()) of
	{ok,_Stats} ->
	    ?debug("bert_rpc_exec: close, stats=~w\n", [_Stats]),
	    {ok, State};
	{error,_Reason} ->
	    ?debug("bert_rpc_exec: close, stats error=~w\n", [_Reason]),
	    {ok, State}
    end.

error(_Socket,Error,State) ->
    ?debug("bert_rpc_exec: error = ~p\n", [Error]),
    {stop, Error, State}.

%%
%% Internal
%%
handle_request(Socket, Request, State) ->
    case Request of
	{call,Module,Function,Arguments} when is_atom(Module),
					      is_atom(Function),
					      is_list(Arguments) ->
	    case access_test(Module,Function,length(Arguments),State) of
		ok ->
		    %% handle security  + stream input ! + stream output
		    try	apply(Module,Function,Arguments) of
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
		{error,ServerCode,Detail} ->
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

reset_state(State) ->
    State#state { stream   = false,
		  cache    = [],
		  callback = [] }.

send_server_error(Socket, ServerCode, Detail, StackTrace) ->
    Trace = encode_stacktrace(StackTrace),
    B = {error,{server,ServerCode,<<"BERTError">>, Detail, Trace}},
    exo_socket:send(Socket, bert:to_binary(B)).

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
		    catch bert_rpc:cast_host(Host,Port, M, F, A ++ [Value]),
		    {ok, State#state { callback = []}};
		_Serv ->
		    ?debug("callback bad service = ~p\n", [_Serv]),
		    {ok, State#state { callback = []}}
	    end
    end.

access_test(M,F,A, State) ->
    Access = State#state.access,
    if Access =:= [] ->  %% full access!!!
	    access_check(M,F,A,State);
       true ->
	    case lists:member(M, Access) of
		false ->
		    case lists:member({M,F,A}, Access) of
			false ->
			    {error, ?SERV_ERR_NO_SUCH_FUNCTION,
			     <<"access denied">>};
			true ->
			    access_check(M,F,A,State)
		    end;
		true ->
		    access_check(M,F,A,State)
	    end
    end.


access_check(M,F,A, _State) ->
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
			    ok;
			false ->
			    {error, ?SERV_ERR_NO_SUCH_FUNCTION,
			     <<"function not defined">>}
		    end;
		true ->
		    ok
	    end
    end.

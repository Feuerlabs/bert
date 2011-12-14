%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%    BERT-RPC
%%% @end
%%% Created : 17 Sep 2011 by Tony Rogvall <tony@rogvall.se>

-module(bert_rpc_exec).

-include("bert.hrl").

%% FIXME add support for ssl negitation security 
-record(server,
	{
	  validation,
	  callback = [],
	  access = []
	}).

-compile(export_all).
-export([init/2, data/3, close/2, error/3]).

start() ->
    start(?BERT_PORT).

start(Port) ->
    bert_tcp_server:start(Port, [{active,once},{packet,4},binary,
				 {reuseaddr,true}], ?MODULE, []).

init(Socket, _Args) ->
    {ok,{IP,Port}} = inet:peername(Socket),
    io:format("bert_rpc_exec: connection from: ~p : ~p\n", [IP, Port]),
    {ok, #server{}}.

data(Socket, Data, Server) ->
    try bert:to_term(Data) of
	Request ->
	    io:format("bert_rpc_exec: request: ~w\n", [Request]),
	    handle_request(Socket, Request, Server)
    catch
	error:_Error ->
	    B = {error,{protcol,0,<<"BERTError">>,
			%% detail
			<<"unable to decode">>,
			%% fixme: encode backtrace
			[]}},
	    gen_tcp:send(Socket, bert:to_binary(B)),
	    {ok,Server}
    end.

close(Socket, Server) ->
    {ok,Stats} = inet:getstat(Socket, inet:stats()),
    io:format("bert_rpc_exec: close, stats=~w\n", [Stats]),
    {ok, Server}.

error(_Socket,Error,Server) ->
    io:format("bert_rpc_exec: error = ~p\n", [Error]),
    {stop, Error, Server}.
	    
%%
%% Internal
%%	
handle_request(Socket, Request, Server) ->
    case Request of
	{call,Module,Function,Arguments} when is_atom(Module),
					      is_atom(Function),
					      is_list(Arguments) ->
	    %% FIXME check validation !!!
	    case check_call(Module,Function,length(Arguments),Server) of
		ok ->
		    %% handle security 
		    try	apply(Module,Function,Arguments) of
			Result ->
			    B = {reply,Result},
			    gen_tcp:send(Socket, bert:to_binary(B)),
			    {ok,Server}
		    catch
			error:_Error ->
			    B = {error,{server,2,<<"BERTError">>,
					%% detail
					<<"fixme detail">>,
					%% fixme: encode backtrace
					[<<"fixme:line:context">>]}},
			    gen_tcp:send(Socket, bert:to_binary(B)),
			    {ok,Server}
		    end;
		{error,ServerCode} ->
		    B = {error,{server,ServerCode,<<"BERTError">>,
				%% detail
				<<"fixme detail">>,
				[]}},
		    gen_tcp:send(Socket, bert:to_binary(B)),
		    {ok,Server}
	    end;
	
	{cast,Module,Function,Arguments} when is_atom(Module),
					      is_atom(Function),
					      is_list(Arguments) ->
	    case check_call(Module,Function,length(Arguments),Server) of
		ok ->
		    B = {noreply},
		    gen_tcp:send(Socket, bert:to_binary(B)),
		    try apply(Module,Function,Arguments) of
			Value ->
			    callback(Value, Server)
		    catch
			error:_ ->
			    {ok,Server#server { callback=[]}}
		    end;
		{error,ServerCode} ->
		    B = {error,{server,ServerCode,<<"BERTError">>,
				%% detail
				<<"fixme detail">>,
				[]}},
		    gen_tcp:send(Socket, bert:to_binary(B)),
		    {ok,Server}
	    end;

	{info, callback, Callback } ->
	    {ok, Server#server { callback = Callback }};

	{info, cache, Validation } ->
	    {ok, Server#server { validation = Validation }};	

	_Other ->
	    B = {error,{server,0,<<"BERTError">>,
			%% detail
			<<"protocol error">>,
			%% backtrace
			[]}},
	    gen_tcp:send(Socket, bert:to_binary(B)),
	    {ok,Server} 
    end.


callback(Value, Server) ->
    case Server#server.callback of
	[] ->
	    {ok,Server};
	[{service,Service},{mfa,M,F,A}] ->
	    case string:tokens(binary_to_list(Service), ":") of
		[Host,PortString] ->
		    Port = list_to_integer(PortString),
		    catch bert_rpc:cast_host(Host,Port, M, F, A ++ [Value]),
		    {ok, Server#server { callback = []}};
		_Serv ->
		    io:format("callback bad service = ~p\n", [_Serv]),
		    {ok, Server#server { callback = []}}
	    end
    end.
    

check_call(M,F,A, _Server) ->
    case code:ensure_loaded(M) of
	false ->
	    {error, ?SERV_ERR_NO_SUCH_MODULE};
	{module,M} ->
	    case erlang:function_exported(M,F,A) of
		false ->
		    case erlang:is_builtin(M,F,A) of
			true ->
			    ok;
			false ->
			    %% FIXME: may be native function
			    {error, ?SERV_ERR_NO_SUCH_FUNCTION}
		    end;
		true ->
		    %% Check access
		    %% case lists:member({M,F,A}, Server#server.access)
		    %% case lists:member({M,F}, Server#server.access)
		    %% case lists:member({M}, Server#server.access)
		    ok
	    end
    end.
		    
		    


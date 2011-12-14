%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%
%%% @end
%%% Created : 22 Aug 2011 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(bert_tcp_server).

-behaviour(gen_server).

%%
%% methods
%%   init(Socket, Args) ->  
%%      {ok, State'}
%%      {stop, Reason, State'}
%%
%%   data(Socket, Data, State) ->
%%      {ok, State'}
%%      {stop, Reason, State'};
%%
%%   close(Socket, State) ->
%%      {ok, State'}
%%      
%%   error(Socket, Error, State) ->
%%      {ok, State'}
%%      {stop, Reason, State'}
%%

%% API
-export([start_link/4, start_link/5]).
-export([start/4, start/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {
	  listen,
	  ref,       %% prim_inet internal accept ref number
	  module,    %% session module
	  args       %% session init args
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Port, Options, Module, Args) ->
    gen_server:start_link(?MODULE, [Port,Options,Module,Args], []).

start_link(ServerName, Port, Options, Module, Args) ->
    gen_server:start_link(ServerName, ?MODULE, [Port,Options,Module,Args], []).

start(Port, Options, Module, Args) ->
    gen_server:start(?MODULE, [Port,Options,Module,Args], []).

start(ServerName, Port, Options, Module, Args) ->
    gen_server:start(ServerName, ?MODULE, [Port,Options,Module,Args], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Port,Options,Module,Args]) ->
    case gen_tcp:listen(Port, Options) of
	{ok,Listen} ->
	    %% using this little trick we avoid code loading
	    %% problem in a module doing blocking accept call
	    case prim_inet:async_accept(Listen, -1) of
		{ok, Ref} ->
		    {ok, #state{ listen=Listen, ref=Ref,
				 module=Module, args=Args
			       }};
		{error, Reason} ->
		    {stop,Reason}		    
	    end;
	{error,Reason} ->
	    {stop,Reason}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({inet_async, L, Ref, {ok,Socket}}, State) when 
      L =:= State#state.listen, Ref =:= State#state.ref ->
    %% using this little trick we avoid code loading
    %% problem in a module doing blocking accept call
    NewAccept = prim_inet:async_accept(L, -1),
    case inet:getopts(L, [active,nodelay,keepalive,delay_send,priority,tos]) of
        {ok, [{active,Active}|Opts]} ->  %% transfer listen options
            case inet:setopts(Socket, Opts) of
                ok ->
		    %% since we have removed the api blanket, we must
		    %% excute some "internal" calls to make it look like
		    %% normal sockets
		    inet_db:register_socket(Socket, inet_tcp),
		    case bert_tcp_session:start(Socket,
					       State#state.module,
					       State#state.args) of
			{ok,Pid} ->
			    gen_tcp:controlling_process(Socket, Pid),
			    gen_server:cast(Pid, {activate,Active});
			_Error ->
			    gen_tcp:close(Socket)
		    end;
			    
                _Error ->
		    gen_tcp:close(Socket)
            end;
        _Error ->
	    gen_tcp:close(Socket)
    end,
    case NewAccept of
	{ok,Ref1} ->
	    {noreply, State#state { ref = Ref1 }};
	{error, Reason} ->
	    {stop, Reason, State}
    end;
handle_info({inet_async, L, Ref, {error,Reason}}, State) when 
      L =:= State#state.listen, Ref =:= State#state.ref ->
    case prim_inet:async_accept(L, -1) of
	{ok,Ref} ->
	    {noreply, State#state { ref = Ref }};
	{error, Reason} ->
	    {stop, Reason, State}
	    %% {noreply, State#state { ref = undefined }}
    end;
    
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    gen_tcp:close(State#state.listen),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

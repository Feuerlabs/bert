%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%   BERT TCP session
%%% @end
%%% Created : 22 Aug 2011 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(bert_tcp_session).

-behaviour(gen_server).

%% API
-export([start/3, start_link/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {
	  module,
	  args,
	  socket,
	  active,
	  state
	 }).

-type socket() :: port().
%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------

-spec start_link(Socket::socket(), Module::atom(), Args::[term()]) ->
			{ok, pid()} | ignore | {error, Error::term()}.

start_link(Socket,Module,Args) ->
    gen_server:start_link(?MODULE, [Socket,Module,Args], []).

-spec start(Socket::socket(), Module::atom(), Args::[term()]) ->
		   {ok, pid()} | ignore | {error, Error::term()}.

start(Socket, Module, Args) ->
    gen_server:start(?MODULE, [Socket,Module,Args], []).


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
init([Socket, Module, Args]) ->
    {ok, #state{ socket=Socket,
		 module=Module,
		 args=Args,
		 state=undefined }}.

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
handle_cast({activate,Active}, State) ->
    case apply(State#state.module, init, [State#state.socket,State#state.args]) of
	{ok,CSt0} ->
	    %% enable active mode here (if ever wanted) once is handled,
	    %% automatically anyway. exit_on_close is default and
	    %% allow session statistics retrieval in the close callback
	    SessionOpts = [{active,Active},{exit_on_close, false}],
	    inet:setopts(State#state.socket, SessionOpts),
	    {noreply, State#state { active = Active, state = CSt0 }};

	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
    
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
handle_info({Proto,Socket,Data}, State) when 
      Socket =:= State#state.socket, (Proto =:= tcp orelse Proto =:= http)->
    CSt0 = State#state.state,
    case apply(State#state.module, data, [Socket,Data,CSt0]) of
	{ok,CSt1} ->
	    if State#state.active == once ->
		    inet:setopts(State#state.socket, [{active,once}]);
	       true ->
		    ok
	    end,
	    {noreply, State#state { state = CSt1 }};

	{close, CSt1} ->
	    gen_tcp:shutdown(State#state.socket, write),
	    {noreply, State#state { state = CSt1 }};

	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
handle_info({tcp_closed,Socket}, State) when Socket =:= State#state.socket ->
    CSt0 = State#state.state,
    case apply(State#state.module, close, [Socket,CSt0]) of
	{ok,CSt1} ->
	    {stop, normal, State#state { state = CSt1 }}
    end;
handle_info({tcp_error,Socket,Error}, State) when Socket =:= State#state.socket ->
    CSt0 = State#state.state,
    case apply(State#state.module, error, [Socket,Error,CSt0]) of
	{ok,CSt1} ->
	    {noreply, State#state { state = CSt1 }};
	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
    
handle_info(_Info, State) ->
    io:format("Got info: ~p\n", [_Info]),
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
    gen_tcp:close(State#state.socket),
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


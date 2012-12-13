%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------

-module(bert_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).
-include_lib("lager/include/log.hrl").

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    Servers = get_servers(),
    ?info("BERT servers = ~p~n", [Servers]),
    Children = childspecs(Servers),
    {ok, { {one_for_one, 5, 10}, Children} }.

childspecs(Servers) ->
    [childspec(S) || S <- Servers].

childspec({Name, Opts}) ->
    {Name, {bert_rpc_exec, start_link, [Opts]},
     permanent, 5000, worker, [bert_rpc_exec]}.

get_servers() ->
    %% If 'setup' is available, query for session settings
    SetupMod = setup,
    OtherServers =
	case lists:keymember(SetupMod, 1, application:loaded_applications()) of
	    true ->
		[S || {_, S} <- SetupMod:find_env_vars(bert_servers)];
	    false ->
		[]
	end,
    All = case application:get_env(servers) of
	      {ok, Servers} when is_list(Servers) ->
		  [Servers | OtherServers];
	      _ ->
		  OtherServers
	  end,
    lists:concat(All).

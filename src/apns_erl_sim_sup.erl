%%% ==========================================================================
%%% Copyright 2016 Silent Circle
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% ==========================================================================

%%%-------------------------------------------------------------------
%% @doc apns_erl_sim top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(apns_erl_sim_sup).

-behaviour(supervisor).

%% API
-export([start_link/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(NUM_ACCEPTORS, 100). % Ranch acceptors

%%====================================================================
%% API functions
%%====================================================================

start_link({TcpProto, Options}=Arg) when (TcpProto == ranch_ssl orelse
                                          TcpProto == ranch_tcp)
                                         andalso is_list(Options) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, Arg).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init({RanchTcpProto, Options}) when (RanchTcpProto == ranch_ssl orelse
                                     RanchTcpProto == ranch_tcp) andalso
                                    is_list(Options) ->
    RanchSupSpec = #{id       => ranch_sup,
                     start    => {ranch_sup, start_link, []},
                     restart  => permanent,
                     shutdown => 5000,
                     type     => supervisor,
                     modules  => [ranch_sup]},

    ListenerSpec = ranch:child_spec(apns_erl_sim_ranch_protocol,
                                    ?NUM_ACCEPTORS,
                                    RanchTcpProto,
                                    Options,
                                    apns_erl_sim_ranch_protocol,
                                    []),

    CacheSpec = #{id       => apns_erl_sim_auth_cache,
                  start    => {apns_erl_sim_auth_cache, start_link, []},
                  restart  => permanent,
                  shutdown => 5000,
                  type     => worker,
                  modules  => [apns_erl_sim_auth_cache]},

    SimOpts = [{jwt_key_path, get_jwt_keypath()}],

    SimSpec = #{id       => apns_erl_sim,
                start    => {apns_erl_sim, start_link, [SimOpts]},
                restart  => permanent,
                shutdown => 5000,
                type     => worker,
                modules  => [apns_erl_sim]},

    Children = [
                RanchSupSpec,
                CacheSpec,
                SimSpec,
                ListenerSpec
               ],

    MaxR = 20,
    MaxT = 20,
    RestartStrategy = {one_for_one, MaxR, MaxT},

    {ok, {RestartStrategy, Children}}.

%%====================================================================
%% Internal functions
%%====================================================================
get_jwt_keypath() ->
    {ok, App} = application:get_application(?MODULE),
    application:get_env(App, jwt_key_path).


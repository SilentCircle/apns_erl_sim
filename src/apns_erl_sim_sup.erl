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

%%====================================================================
%% API functions
%%====================================================================

start_link(Options) when is_list(Options) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, Options).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init(Options) when is_list(Options) ->
    RanchSupSpec = #{id       => ranch_sup,
                     start    => {ranch_sup, start_link, []},
                     restart  => permanent,
                     shutdown => 5000,
                     type     => supervisor,
                     modules  => [ranch_sup]},

    ListenerSpec = ranch:child_spec(chatterbox_ranch_protocol,
                                    10,
                                    ranch_ssl,
                                    Options,
                                    chatterbox_ranch_protocol,
                                    []),

    SimSpec = #{id       => apns_erl_sim,
                start    => {apns_erl_sim, start_link, []},
                restart  => permanent,
                shutdown => 5000,
                type     => worker,
                modules  => [apns_erl_sim]},

    Children = [
                RanchSupSpec,
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

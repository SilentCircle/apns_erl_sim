%%%-------------------------------------------------------------------
%% @doc apns_erl_sim public API
%% @end
%%%-------------------------------------------------------------------

-module(apns_erl_sim_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    Options = default_options(),
    {ok, App} = application:get_application(?MODULE),
    setup_env(code:priv_dir(App)),
    apns_erl_sim_sup:start_link(Options).

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

setup_env(RootDir) ->
    application:set_env(
      chatterbox,
      stream_callback_mod,
      chatterbox_static_stream),

    application:set_env(
      chatterbox,
      chatterbox_static_stream,
      [{root_dir, RootDir}]).

%% Set up default socket options
default_options() ->
    [
     {port, 2197},
     {certfile, "localhost.crt"},
     {keyfile, "localhost.key"},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {next_protocols_advertised, [<<"h2">>]}
    ].


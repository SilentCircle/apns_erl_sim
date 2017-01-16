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
    setup_env(),
    RanchTcpProto = case application:get_env(chatterbox, ssl) of
                        {ok, true} -> ranch_ssl;
                        _          -> ranch_tcp
                    end,
    Options = case application:get_env(chatterbox, ssl_options) of
                  {ok, SslOpts} -> SslOpts;
                  _             -> default_options(RanchTcpProto)
              end,
    apns_erl_sim_sup:start_link({RanchTcpProto, Options}).

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

setup_env() ->
    application:set_env(chatterbox, stream_callback_mod, apns_erl_sim_stream).

%% Set up default socket options
default_options(ranch_tcp) ->
    [
     {port, 2197}
    ];
default_options(ranch_ssl) ->
    [
     {port, 2197},
     {certfile, "localhost.crt"},
     {keyfile, "localhost.key"},
     {cacertfile, "/etc/ssl/certs/ca-certificates.crt"},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {verify, verify_peer},
     {fail_if_no_peer_cert, true},
     {next_protocols_advertised, [<<"h2">>]}
    ].


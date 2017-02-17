-module(apns_erl_sim_ranch_protocol).
-behaviour(ranch_protocol).

-include_lib("chatterbox/include/http2.hrl").

-export([
         start_link/4,
         init/4
        ]).

start_link(Ref, Socket, Transport, ProtocolOpts) ->
    Pid = proc_lib:spawn_link(?MODULE, init,
                              [Ref, Socket, Transport, ProtocolOpts]),
    {ok, Pid}.

init(Ref, Socket, T, ProtocolOpts) ->
    ok = ranch:accept_ack(Ref),
    Transport = {transport(T), Socket},

    %% Override MCS based on whether or not an ssl connection has a peer
    %% certificate.  If there is a peer cert, the connection is considered
    %% authenticated by cert, and MCS can be the APNS maximum (500). If there
    %% is no peer cert, the connection is considered to be authenticated by
    %% JWT, and according to the APNS docs, MCS starts off at 1 until the first
    %% valid JWT has been received and verified.
    Http2Settings = set_mcs(Transport,
                            proplists:get_value(http2_settings, ProtocolOpts,
                                                chatterbox:settings(server))),

    h2_connection:become(Transport, Http2Settings).

transport(ranch_ssl) ->
    ssl;
transport(ranch_tcp) ->
    gen_tcp;
transport(tcp) ->
    gen_tcp;
transport(gen_tcp) ->
    gen_tcp;
transport(ssl) ->
    ssl;
transport(Other) ->
    lager:error("~p doesn't support ~p", [?MODULE, Other]),
    error(unknown_protocol).

set_mcs({ssl, Socket}, Settings) ->
    {Status, MCS} = case ssl:peercert(Socket) of
                        {ok, _Cert} -> {"found", 500};
                        {error, _}  -> {"did not find", 1}
                    end,
    lager:debug("~p ~s peer cert, set MCS = ~p", [?MODULE, Status, MCS]),
    Settings#settings{max_concurrent_streams=MCS};
set_mcs(_, Settings) ->
    Settings.

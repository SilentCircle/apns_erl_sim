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

-module(apns_erl_sim_stream).
-behaviour(h2_stream).

%%%====================================================================
%%% Includes
%%%====================================================================
-include_lib("chatterbox/include/http2.hrl").
-include_lib("public_key/include/public_key.hrl").

%%%====================================================================
%%% Behaviour exports
%%%====================================================================
-export([
         init/2,
         on_receive_request_headers/2,
         on_send_push_promise/2,
         on_receive_request_data/2,
         on_request_end_stream/1
        ]).

%%%====================================================================
%%% Defines
%%%====================================================================
-define(MAX_PAYLOAD, 4096).
-define(S, ?MODULE).

%%%====================================================================
%%% Records
%%%====================================================================
-type h2_header() :: {binary(), binary()}.
-type h2_headers() :: [h2_header()].
-type h2_data() :: binary().

-record(req, {
          headers = []   :: h2_headers(),
          data    = <<>> :: h2_data()
         }).

-type req_rec() :: #req{}.

-record(stream, {
          conn_pid :: pid(),
          id       :: stream_id()
         }).

-type stream_rec() :: #stream{}.

-record(?S, {
           req      = #req{} :: req_rec(),
           stream   = #stream{} :: stream_rec(),
           reasons  = reasons() :: map(),
           sts_hdrs = status_hdrs() :: map(),
           peercert = #{} :: map()
          }).

-type state() :: #?S{}.

%%%====================================================================
%%% h2_stream callback functions
%%%====================================================================
-spec init(ConnPid, StreamId) -> Result when
      ConnPid :: pid(), StreamId :: stream_id(), Result :: {ok, state()}.
init(ConnPid, StreamId) ->
    %% You need to pull settings here from application:env or something
    {ok, make_state(ConnPid, StreamId)}.

%%--------------------------------------------------------------------
-spec on_receive_request_headers(Headers, State) -> Result when
      Headers :: h2_headers(), State :: state(), Result :: {ok, state()}.
on_receive_request_headers(Headers, #?S{req=Req, stream=Strm}=State) ->
    lager:info("[~p:~p][StrId:~B] on_receive_request_headers(~p, ~p)",
               [?MODULE, self(), Strm#stream.id, Headers, Req]),
    {ok, PeerCertDer} = h2_connection:get_peercert(Strm#stream.conn_pid),
    PeerCert = apns_cert:der_decode_cert(PeerCertDer),
    PeerCertInfo = apns_cert:get_cert_info_map(PeerCert),
    {ok, State#?S{req=Req#req{headers=Headers}, peercert=PeerCertInfo}}.

%%--------------------------------------------------------------------
on_send_push_promise(Headers, #?S{stream=Stream, req=Req}=State) ->
    lager:info("[~p:~p][StrId:~B] on_send_push_promise(~p, ~p)",
               [?MODULE, self(), Stream#stream.id, Headers, Req]),
    {ok, State#?S{req=Req#req{headers=Headers}}}.

%%--------------------------------------------------------------------
on_receive_request_data(Bin, #?S{stream=Stream, req=Req}=State)->
    lager:info("[~p:~p][StrId:~B] on_receive_request_data(~p, ~p)",
               [?MODULE, self(), Stream#stream.id, Bin, Req]),
    {ok, State#?S{req=Req#req{data=Bin}}}.

%%--------------------------------------------------------------------
on_request_end_stream(#?S{stream=Stream, req=Req} = State) ->
    lager:info("[~p:~p][StrId:~B] on_request_end_stream(~p)",
               [?MODULE, self(), Stream, Req]),
    Headers = Req#req.headers,
    Method = proplists:get_value(<<":method">>, Headers),
    Path = binary_to_list(proplists:get_value(<<":path">>, Headers)),

    lager:debug("[~p:~p][StrId:~B] method:~s path:~s",
                [?MODULE, self(), Stream#stream.id, Method, Path]),

    handle_request(Method, Path, Headers, State),

    {ok, State}.


%%%====================================================================
%%% Internal functions
%%%====================================================================

%%--------------------------------------------------------------------
make_state(ConnPid, StreamId) ->
    #?S{stream = #stream{conn_pid = ConnPid, id = StreamId}}.

%%--------------------------------------------------------------------
-spec generate_push_promise_headers(hpack:headers(), binary()) -> hpack:headers().
generate_push_promise_headers(Request, Path) ->
    [
     {<<":path">>, Path},{<<":method">>, <<"GET">>}|
     lists:filter(fun({<<":authority">>,_}) -> true;
                     ({<<":scheme">>, _}) -> true;
                     (_) -> false end, Request)
    ].


%%--------------------------------------------------------------------
handle_request(Method, Path, Headers, #?S{stream=#stream{id=SID,
                                                         conn_pid=CID}}=St) ->
    Rsp = make_response(Method, Path, Headers, St),
    lager:debug("[~p:~p][StrId:~B] sending response ~p",
                [?MODULE, self(), SID, Rsp]),
    send_response(CID, SID, Rsp).


%%--------------------------------------------------------------------
make_response(<<"POST">>, "/3/device/" ++ Token, Headers, #?S{} = State) ->
    handle_post(Headers, Token, State);
make_response(<<"POST">>, _Other, Headers, #?S{}=S) ->
    response_from_reason('BadPath', [apns_id_hdr(Headers)], S);
make_response(_, _Other, Headers,  #?S{}=S) ->
    response_from_reason('MethodNotAllowed', [apns_id_hdr(Headers)], S).


%%--------------------------------------------------------------------
handle_post(Headers, Token, #?S{req=#req{data=Payload},
                                stream=Stream,
                                peercert=Cert}=S) ->
    try
        ApnsIdHdr = case check_apns_id_hdr(Headers) of
                        {ok, Hdr} ->
                            Hdr;
                        {BadApnsId, Hdr} ->
                            throw({status_with_apns_id, {BadApnsId, Hdr}})
                    end,
        RespHdrs = [ApnsIdHdr],
        check_token(Token),
        JSON = check_payload(Payload),
        ReqMap = check_headers(Headers, Cert, JSON),
        lager:info("[~p:handle_post:~p][StrId:~B] JSON: ~p",
                   [?MODULE, self(), Stream#stream.id, JSON]),
        lager:info("[~p:handle_post:~p][StrId:~B] ReqMap: ~p",
                   [?MODULE, self(), Stream#stream.id, ReqMap]),
        handle_req_map(ReqMap, RespHdrs, S)
    catch
        error:{badmatch, Status} ->
            response_from_reason(Status, [apns_id_hdr(Headers)], S);
        throw:{status_with_apns_id, {Status, IdHdr}} ->
            response_from_reason(Status, [IdHdr], S);
        throw:{status, Status} ->
            response_from_reason(Status, [apns_id_hdr(Headers)], S)
    end.

%%--------------------------------------------------------------------
handle_req_map(ReqMap, RespHdrs, #?S{stream=Stream}=S) ->
    %% TODO: maybe validate the request JSON, but could be lots of work for
    %% little reward
    %% validate_aps_json(ReqMap)
    SimCfg = get_sim_cfg(ReqMap),
    {Response, Delay} = make_sim_response(SimCfg, RespHdrs, S),
    case Delay of
        Ms when is_integer(Ms), Ms =< 0 ->
            ok;
        Ms when is_integer(Ms) ->
            lager:info("[~p:handle_req_map:~p][StrId:~B] Delaying for ~B ms",
                       [?MODULE, self(), Stream#stream.id, Delay]),
            receive after Ms -> ok end
    end,
    Response.

%%--------------------------------------------------------------------
-define(pv(K, Cfg, Default), proplists:get_value(K, Cfg, Default)).
-define(sim_status_code(Cfg), sc_util:to_bin(?pv(<<"status_code">>, Cfg, <<>>))).
-define(sim_body(Cfg), base64:decode(?pv(<<"body">>, Cfg, <<>>))).
-define(sim_delay(Cfg), ?pv(<<"delay">>, Cfg, 0)).
-define(sim_reason(Cfg), ?pv(<<"reason">>, Cfg, <<>>)).

-define (dbg_msg(Fmt, Args),
         lager:info("[~s:~B] " ++ Fmt,
                    [filename:basename(?FILE), ?LINE] ++ Args)).

% Precedence is:
%
% - body trumps reason
% - status_code must be provided if body is provided
% - status_code overrides reason
%
% The valid combinations are:
%
% - status_code and body
% - reason
% - status_code and reason
%
make_sim_response(SimCfg, RespHdrs, S) ->
    StatusCode = ?sim_status_code(SimCfg),
    Reason = ?sim_reason(SimCfg),
    Body = ?sim_body(SimCfg),
    Delay = ?sim_delay(SimCfg),

    ?dbg_msg("StatusCode = ~p\n", [StatusCode]),
    ?dbg_msg("Reason = ~p\n", [Reason]),
    ?dbg_msg("Body = ~p\n", [Body]),
    ?dbg_msg("Delay = ~p\n", [Delay]),

    {StsHdr, BodyOverride} = get_sim_sts_body(StatusCode, Reason, S),
    ?dbg_msg("StsHdr = ~p\n", [StsHdr]),
    ?dbg_msg("BodyOverride = ~p\n", [BodyOverride]),
    Response = {[StsHdr | RespHdrs], maybe_override_body(Body, BodyOverride)},
    ?dbg_msg("Response = ~p\n", [Response]),
    {Response, Delay}.


%%--------------------------------------------------------------------
get_sim_sts_body(StatusCode, Reason, #?S{} = S) ->
    case {StatusCode, Reason} of
        {<<>>, <<>>} ->
            {{<<":status">>, <<"200">>}, undefined};
        {<<"200">>, <<>>} ->
            {{<<":status">>, <<"200">>}, undefined};
        {<<SC/binary>>, <<>>} when SC /= <<>> ->
            Rsn = reason_for_status_code(SC),
            status_hdr(Rsn, S#?S.sts_hdrs);
        {<<>>, <<Rsn/binary>>} when Rsn /= <<>> ->
            status_hdr(b2a(Rsn), S#?S.sts_hdrs);
        {<<SC/binary>>, <<Rsn/binary>>} ->
            encode_status_hdr({<<":status">>, SC}, b2a(Rsn))
    end.

%%--------------------------------------------------------------------
maybe_override_body(<<>>, OBody) ->
    OBody;
maybe_override_body(Body, undefined) ->
    Body;
maybe_override_body(_Body, OBody) ->
    OBody.

%%--------------------------------------------------------------------
get_sim_cfg(#{apns_json := JSON}) ->
    proplists:get_value(<<"sim_cfg">>, JSON, []).

%%--------------------------------------------------------------------
send_response(ConnPid, StreamId, {Headers, Body}) ->
    {Opts, SendBody} = send_opts(Body),
    h2_connection:send_headers(ConnPid, StreamId, Headers, Opts),
    SendBody andalso h2_connection:send_body(ConnPid, StreamId, Body).

%%--------------------------------------------------------------------
send_opts(undefined) ->
    {[{send_end_stream, true}], false};
send_opts(_) ->
    {[], true}.

%%--------------------------------------------------------------------
-spec apns_id_hdr(Headers) -> Result when
      Headers :: h2_headers(), Result :: h2_header().
apns_id_hdr(Headers) ->
    {_, Hdr} = check_apns_id_hdr(Headers),
    Hdr.

%%--------------------------------------------------------------------
-define(UUID_RE, "^[[:xdigit:]]{8}(?:-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$").

-spec check_apns_id_hdr(Headers) -> Result when
      Headers :: h2_headers(), Result :: {ok | 'BadMessageId', h2_header()}.
check_apns_id_hdr(Headers) ->
    case lists:keyfind(<<"apns-id">>, 1, Headers) of
        {<<"apns-id">>, UUID} = Hdr ->
            case re:run(binary_to_list(UUID), ?UUID_RE, [{capture, none}]) of
                match ->
                    {ok, Hdr};
                nomatch ->
                    {'BadMessageId', make_apns_id_hdr()}
            end;
        false ->
            {ok, make_apns_id_hdr()}
    end.

%%--------------------------------------------------------------------
make_apns_id_hdr() ->
    UUID = string:to_upper(binary_to_list(apns_lib_http2:make_uuid())),
    {<<"apns-id">>, sc_util:to_bin(UUID)}.

%%--------------------------------------------------------------------
check_headers(Headers, Cert, JSON) ->
    %RespHdrs = [apns_id_hdr(Headers)],
    UUID = apns_id_hdr(Headers),

    Topic = proplists:get_value(<<"apns-topic">>, Headers),
    {UseTopic, App} = check_topic(Topic, Cert),

    Exp = proplists:get_value(<<"apns-expiration">>, Headers),
    {ok, UseExp} = check_expiration(Exp),

    Prio = proplists:get_value(<<"apns-priority">>, Headers),
    APS = proplists:get_value(<<"aps">>, JSON, []),
    ContentAvailable = proplists:get_value(<<"content-available">>, APS),
    Count = length(APS),
    {ok, UsePrio} = check_priority(Prio, ContentAvailable, Count),

    #{apns_topic => UseTopic,
      apns_expiration => UseExp,
      apns_priority => UsePrio,
      apns_json => JSON,
      apns_aps_dict => APS,
      apns_id => UUID,
      cert_app => App}.

%%--------------------------------------------------------------------
check_token(Token) ->
    try
        32 = byte_size(sc_util:hex_to_bitstring(Token))
    catch
        _:_ ->
            throw({status, 'BadDeviceToken'})
    end.


%%--------------------------------------------------------------------
check_payload(Payload) ->
    case byte_size(Payload) of
        0 ->
            throw({status, 'PayloadEmpty'});
        N when N > ?MAX_PAYLOAD ->
            throw({status, 'PayloadTooLarge'});
        _ ->
            try jsx:decode(Payload)
            catch
                _:_ ->
                    [{}] % empty dict
            end
    end.


%%--------------------------------------------------------------------
-spec check_topic(ApnsTopic, CertInfo) -> Result when
      ApnsTopic :: undefined | binary(), CertInfo :: map(),
      Result :: 'BadCertificate'
              | 'InternalServerError'
              | 'MissingTopic'
              | {Topic, App},
      Topic :: binary(), App :: undefined | binary().
check_topic(ApnsTopic, CertInfo) ->
    Topics = get_cert_topics(CertInfo),
    IsMultTopics = is_list(Topics),
    CertSubjUid = get_cert_subject_uid(CertInfo),
    IsValidCertUid = CertSubjUid /= undefined,

    if
        not (IsMultTopics orelse IsValidCertUid) ->
            'BadCertificate';
        ApnsTopic == undefined ->
            get_default_topic(IsMultTopics, CertSubjUid);
        IsMultTopics ->
            get_topic_from_topics(ApnsTopic, Topics);
        ApnsTopic == CertSubjUid ->
            {CertSubjUid, undefined};
        true ->
            'BadTopic'
    end.


%%--------------------------------------------------------------------
get_cert_topics(#{topics := Topics}) ->
    Topics.

%%--------------------------------------------------------------------
get_cert_subject_uid(#{subject_uid := Topic}) ->
    Topic.

%%--------------------------------------------------------------------
get_default_topic(true = _IsMultTopics, _CertSubjUid) ->
    %% No topic provided and multiple topics exist is an error
    'MissingTopic';
get_default_topic(false = _IsMultTopics, CertSubjUid) ->
    %% No topic provided and no multiple topics: use cert subject uid
    {CertSubjUid, undefined}.

%%--------------------------------------------------------------------
get_topic_from_topics(Topic, Topics) when is_list(Topics) ->
    case lists:keysearch(Topic, 1, Topics) of
        {value, {Topic, _App}=TA} ->
            TA;
        _ ->
            'BadTopic'
    end.

%%--------------------------------------------------------------------
check_expiration(undefined) ->
    {ok, 16#7FFFFFFF};
check_expiration(Exp) ->
    try list_to_integer(binary_to_list(Exp)) of
        0 ->
            {ok, expire_immediately};
        N ->
            check_if_expired(N)
    catch
        _:_ ->
            'BadExpirationDate'
    end.

%%--------------------------------------------------------------------
%% 10–Send the push message immediately. Notifications with this priority must
%% trigger an alert, sound, or badge on the target device. It is an error to
%% use this priority for a push notification that contains only the
%% content-available key.
%%--------------------------------------------------------------------
check_priority(undefined, ContentAvailable, KeyCount) ->
    check_content_available_key(10, ContentAvailable, KeyCount);
check_priority(Prio, ContentAvailable, KeyCount) ->
    try list_to_integer(binary_to_list(Prio)) of
        5 ->
            {ok, 5};
        10 ->
            check_content_available_key(10, ContentAvailable, KeyCount);
        _ ->
            'BadPriority'
    catch
        _:_ ->
            'BadPriority'
    end.

%%--------------------------------------------------------------------
check_if_expired(N) ->
    case sc_util:posix_time() >= N of
        true ->
            {ok, expire_immediately};
        false ->
            {ok, N}
    end.

%%--------------------------------------------------------------------
check_content_available_key(10, undefined, _KeyCount) ->
    {ok, 10};
check_content_available_key(10, _ContentAvailable, 1) ->
    'BadPriority';
check_content_available_key(Prio, _ContentAvailable, _KeyCount) ->
    {ok, Prio}.

%%--------------------------------------------------------------------
-spec reason(Rsn, RsnMap) -> Json when
      Rsn :: atom(), RsnMap :: map(), Json :: binary().
reason(Rsn, RsnMap) when is_atom(Rsn) andalso is_map(RsnMap) ->
    maps:get(Rsn, RsnMap).


%%--------------------------------------------------------------------
-spec status_hdr(Rsn, StsMap) -> Result when
      Rsn :: atom(), StsMap :: map(),
      Result :: {StsHdr, JSON}, StsHdr :: {Key, Val}, JSON :: binary(),
      Key :: binary(), Val :: binary().
status_hdr(Rsn, StsMap) when is_atom(Rsn) andalso is_map(StsMap) ->
    case maps:find(Rsn, StsMap) of
        {ok, Val} ->
            encode_status_hdr(Val, Rsn);
        error ->
            {{<<":status">>, <<"400">>},
             jsx:encode([{reason, list_to_binary([<<"Unknown reason: ">>,
                                                  atom_to_list(Rsn)])}])}
    end.


%%--------------------------------------------------------------------
encode_status_hdr({<<":status">>, Sts} = Val, Rsn) when is_binary(Sts),
                                                        is_atom(Rsn) ->
    {Val, jsx:encode([
                      {reason, list_to_binary(atom_to_list(Rsn))}
                     ] ++ maybe_ts(Sts))}.

%%--------------------------------------------------------------------
maybe_ts(<<"410">>) ->
    [{timestamp, erlang:system_time(milli_seconds)}];
maybe_ts(_) ->
    [].

%%--------------------------------------------------------------------
response_from_reason(ReasonName, ExtraHdrs, S) when is_atom(ReasonName) ->
    {StsHdr, Reason} = status_hdr(ReasonName, S#?S.sts_hdrs),
    {[StsHdr | ExtraHdrs], Reason}.

%%--------------------------------------------------------------------
reason_for_status_code(Sts) ->
    case lists:keyfind(Sts, 2, apns_erl_sim_stream:status_list()) of
        {Reason, _} ->
            Reason;
        false ->
            'InternalServerError'
    end.

%%--------------------------------------------------------------------
maybe_reason(success, _) ->
    undefined;
maybe_reason(ReasonName, S) ->
    reason(ReasonName, S#?S.reasons).

%%--------------------------------------------------------------------
-spec reasons() -> map().
reasons() ->
    maps:from_list([{b2a(B), jsx:encode([{reason, B}])} || B <- reason_list()]).


%%--------------------------------------------------------------------
reason_list() ->
    [
     <<"BadCertificate">>,
     <<"BadCertificateEnvironment">>,
     <<"BadDeviceToken">>,
     <<"BadExpirationDate">>,
     <<"BadMessageId">>,
     <<"BadPath">>,
     <<"BadPriority">>,
     <<"BadTopic">>,
     <<"DeviceTokenNotForTopic">>,
     <<"DuplicateHeaders">>,
     <<"Forbidden">>,
     <<"IdleTimeout">>,
     <<"InternalServerError">>,
     <<"MethodNotAllowed">>,
     <<"MissingDeviceToken">>,
     <<"MissingTopic">>,
     <<"PayloadEmpty">>,
     <<"PayloadTooLarge">>,
     <<"ServiceUnavailable">>,
     <<"Shutdown">>,
     <<"TooManyRequests">>,
     <<"TopicDisallowed">>,
     <<"Unregistered">>
    ].


%%--------------------------------------------------------------------
status_hdrs() ->
    maps:from_list(
      [{K, {<<":status">>, V}} || {K, V} <- status_list()]
     ).

%%--------------------------------------------------------------------
status_list() ->
    [
     {'BadCertificate',             <<"403">>},
     {'BadCertificateEnvironment',  <<"403">>},
     {'BadDeviceToken',             <<"400">>},
     {'BadExpirationDate',          <<"400">>},
     {'BadMessageId',               <<"400">>},
     {'BadPath',                    <<"400">>},
     {'BadPriority',                <<"400">>},
     {'BadTopic',                   <<"400">>},
     {'DeviceTokenNotForTopic',     <<"400">>},
     {'DuplicateHeaders',           <<"400">>},
     {'Forbidden',                  <<"400">>},
     {'IdleTimeout',                <<"503">>},
     {'InternalServerError',        <<"500">>},
     {'MethodNotAllowed',           <<"405">>},
     {'MissingDeviceToken',         <<"400">>},
     {'MissingTopic',               <<"400">>},
     {'PayloadEmpty',               <<"400">>},
     {'PayloadTooLarge',            <<"413">>},
     {'ServiceUnavailable',         <<"503">>},
     {'Shutdown',                   <<"503">>},
     {'TooManyRequests',            <<"429">>},
     {'TopicDisallowed',            <<"400">>},
     {'Unregistered',               <<"410">>},
     {success,                      <<"200">>}
    ].


%%--------------------------------------------------------------------
b2a(<<B/binary>>) ->
    list_to_atom(binary_to_list(B)).

%%--------------------------------------------------------------------
example_cert_info() ->
    #{bundle_id => undefined,
      bundle_info => undefined,
      expiry_status => "Unexpired",
      is_development => true,
      is_production => true,
      issuer_c => "US",
      issuer_cn => <<"Apple Worldwide Developer Relations Certification Authority">>,
      issuer_l => undefined,
      issuer_o => <<"Apple Inc.">>,
      issuer_ou => <<"Apple Worldwide Developer Relations">>,
      issuer_st => undefined,
      not_after => "Aug 24 18:06:19 2018 GMT",
      not_before => "Aug 24 18:06:19 2016 GMT",
      serial_number => 13,
      subject_c => "US",
      subject_cn => <<"Apple Push Services: com.example.FakeApp">>,
      subject_l => undefined,
      subject_o => <<"Example, LLC">>,
      subject_ou => <<"6F44JJ9SDF">>,
      subject_st => undefined,
      subject_uid => <<"com.example.FakeApp">>,
      topics => [
                 {<<"com.example.FakeApp">>,<<"app">>},
                 {<<"com.example.FakeApp.voip">>,<<"voip">>},
                 {<<"com.example.FakeApp.complication">>, <<"complication">>}
                ]
     }.

%%--------------------------------------------------------------------
example_topics_extension() ->
    #'Extension'{extnID = {1,2,840,113635,100,6,3,6},
                 critical = false,
                 extnValue = <<48,112,12,19,99,111,109,46,101,120,97,109,
                               112,108,101,46,70,97,107,101,65,112,112,
                               48,5,12,3,97,112,112,12,24,99,111,109,46,
                               101,120,97,109,112,108,101,46,70,97,107,
                               101,65,112,112,46,118,111,105,112,48,6,12,
                               4,118,111,105,112,12,32,99,111,109,46,101,
                               120,97,109,112,108,101,46,70,97,107,101,
                               65,112,112,46,99,111,109,112,108,105,99,
                               97,116,105,111,110,48,14,12,12,99,111,109,
                               112,108,105,99,97,116,105,111,110>>}.

%% ex: set ft=erlang ts=4 sts=4 sw=4 et:

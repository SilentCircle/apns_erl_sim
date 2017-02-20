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
-define(MAX_CONCURRENT_STREAMS, 500).
-define(MIN_CONCURRENT_STREAMS, 1).
-define(JWT_EXPIRY, 3600). % 1 hour past iat

-define(UUID_RE, "^[[:xdigit:]]{8}(?:-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$").

-define(S, ?MODULE).

%%%====================================================================
%%% Records
%%%====================================================================
-type h2_header() :: {binary(), binary()}.
-type h2_headers() :: [h2_header()].
-type h2_data() :: binary().

-record(req, {
          headers = []   :: h2_headers(),
          data    = <<>> :: h2_data(),
          map     = #{}  :: map()
         }).

-type req_rec() :: #req{}.

-record(rsp, {
          headers = []   :: h2_headers(),
          data    = <<>> :: h2_data()
         }).

-type rsp_rec() :: #rsp{}.

-record(stream, {
          conn_pid  :: pid(),
          id        :: stream_id()
         }).

-type stream_rec() :: #stream{}.

-type ec_private_key() :: #'ECPrivateKey'{}.

-record(?S, {
           req          = #req{} :: req_rec(),
           rsp          = undefined :: undefined | rsp_rec(), % Only for header-based errors
           peercert     = undefined :: undefined | none | map(),
           mcs_changed  = false :: boolean(),
           %% These don't change once assigned
           stream       = #stream{} :: stream_rec(),
           uuid_re      = undefined :: undefined | re:mp(),
           reasons      = reasons() :: map(),
           sts_hdrs     = status_hdrs() :: map()
          }).

-type state() :: #?S{}.

%%%====================================================================
%%% h2_stream callback functions
%%%====================================================================
%% Warning: There cannot be any calls to h2_connection etc in this
%% function, because it causes a deadlock.
-spec init(ConnPid, StrmId) -> Result when
      ConnPid :: pid(), StrmId :: stream_id(), Result :: {ok, state()}.
init(ConnPid, StrmId) ->
    State = make_state(ConnPid, StrmId),
    {ok, State}.

%%--------------------------------------------------------------------
-spec on_receive_request_headers(Headers, State) -> Result when
      Headers :: h2_headers(), State :: state(), Result :: {ok, state()}.
on_receive_request_headers(Headers, #?S{uuid_re=RE}=S) ->
    Res = try handle_request_headers_nocatch(Headers, S) of
              R ->
                  R
          catch
              error:{badmatch, Status}=Exc ->
                  lager:error("Reqhdr exception: ~p", [Exc]),
                  response_from_reason(Status, [apns_id_hdr(Headers, RE)], S);
              throw:{status_with_apns_id, {Status, IdHdr}}=Exc ->
                  lager:error("Reqhdr exception: ~p", [Exc]),
                  response_from_reason(Status, [IdHdr], S);
              throw:{status, Status}=Exc ->
                  lager:error("Reqhdr exception: ~p", [Exc]),
                  response_from_reason(Status, [apns_id_hdr(Headers, RE)], S)
          end,
    result_to_state(Res, S).

%%--------------------------------------------------------------------
on_send_push_promise(Headers, #?S{stream=Strm, req=Req}=State) ->
    lager:info("[StrId:~B] Hdrs: ~p, Req: ~p", [Strm#stream.id, Headers, Req]),
    {ok, State#?S{req=Req#req{headers=Headers}}}.

%%--------------------------------------------------------------------
%% Since we can receive multiple DATA frames in a single stream, append any
%% data received to the data we have in the state. Because chatterbox maintains
%% a separate state variable for each stream, which is (presumably) destroyed
%% after the end of the stream, this should work correctly.
%%
on_receive_request_data(Bin, #?S{stream=Strm, req=#req{data=Data}=Req}=State) ->
    lager:info("[StrId:~B]\nData: ~p\nReq: ~p", [Strm#stream.id, Bin, Req]),
    {ok, State#?S{req=Req#req{data = <<Data/binary, Bin/binary>>}}}.

%%--------------------------------------------------------------------
on_request_end_stream(#?S{stream=#stream{id=StrmId,
                                         conn_pid=ConnId}, rsp=#rsp{}=R}=S) ->
    Rsp = {R#rsp.headers, R#rsp.data},
    lager:warning("[StrId:~B] sending error response ~p", [StrmId, Rsp]),
    send_response(ConnId, StrmId, Rsp),
    {ok, S#?S{req=#req{}, rsp=#rsp{}}}; % Be paranoid and clear req/rsp data
on_request_end_stream(#?S{stream=#stream{id=StrmId}, req=Req} = State) ->
    lager:info("[StrId:~B] Req: ~p", [StrmId, Req]),
    Headers = Req#req.headers,
    Method = pv(<<":method">>, Headers, <<>>),
    Path = binary_to_list(pv(<<":path">>, Headers, <<>>)),
    lager:debug("[StrId:~B] method:~p path:~p", [StrmId, Method, Path]),
    handle_request(Method, Path, State),
    {ok, State#?S{req=#req{}}}. % Be paranoid and clear req data


%%%====================================================================
%%% Internal functions
%%%====================================================================

result_to_state({ok, #?S{}}=Res, _S) ->
    Res;
result_to_state({RspHdrs, RspBody}, #?S{}=S) ->
    {ok, S#?S{rsp=#rsp{headers=RspHdrs, data=RspBody}}}.

%%--------------------------------------------------------------------
make_state(ConnPid, StrmId) ->
    {ok, RE} = re:compile(?UUID_RE),
    #?S{uuid_re=RE,
        stream=#stream{conn_pid=ConnPid, id=StrmId}}.


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
handle_request_headers_nocatch(Headers, #?S{uuid_re=RE,
                                            req=Req,
                                            stream=#stream{conn_pid=CID,
                                                           id=SID},
                                            peercert=undefined,
                                            mcs_changed=MCSCh0}=State) ->
    lager:info("[StrId:~B] Hdrs: ~p\nReq: ~p", [SID, Headers, Req]),
    case check_jwt_auth(Headers) of
        {ok, {Status, _JWT}} ->
            ReqMap = check_headers(Headers, undefined, RE),
            MCSCh = maybe_maximize_mcs(CID, Status, MCSCh0),
            {ok, State#?S{req=Req#req{headers=Headers, map=ReqMap},
                          mcs_changed=MCSCh}};
        {error, Status} when is_atom(Status) ->
            lager:warning("[StrId:~B] JWT auth FAILED: ~p\nHdrs: ~p",
                          [SID, Status, Headers]),
            ExtraHdrs = [apns_id_hdr(Headers, RE)],
            {RspHdrs, RspBody} = response_from_reason(Status, ExtraHdrs,
                                                      State),
            {ok, State#?S{rsp=#rsp{headers=RspHdrs, data=RspBody}}};
        no_auth_header ->
            case maybe_get_cert_info(CID) of
                {ok, PeerCert} -> % Ok, it's cert-based
                    ReqMap = check_headers(Headers, PeerCert, RE),
                    lager:debug("[StrId:~B] Using cert-based auth", [SID]),
                    {ok, State#?S{req=Req#req{headers=Headers, map=ReqMap},
                                  peercert=PeerCert}};
                {error, Reason} -> % well, darn, and there's no auth header.
                    ExtraHdrs = [apns_id_hdr(Headers, RE)],
                    lager:warning("[StrId:~B] Missing provider token "
                                  "because of ~p", [SID, {error, Reason}]),
                    Status = 'MissingProviderToken',
                    {RspHdrs, RspBody} = response_from_reason(Status,
                                                              ExtraHdrs,
                                                              State),
                    {ok, State#?S{rsp=#rsp{headers=RspHdrs, data=RspBody}}}
            end
    end.

%%--------------------------------------------------------------------
maybe_get_cert_info(CID) ->
    case get_auth_method(CID) of
        {cert, PeerCert} -> % Ok, it's cert-based
            {ok, PeerCert};
        {token, _} -> % well, darn - no auth header.
            {error, 'MissingProviderToken'}
    end.

%%--------------------------------------------------------------------
maybe_maximize_mcs(CID, changed=_Status, false=_MCSChanged) ->
    %% If change_MCS doesn't work, don't crash this because
    %% it's likely that the connection has dropped, so let the
    %% connection handle it - it's not fatal if MCS stays at 1
    %% until this stream goes away.
    _ = change_MCS(?MAX_CONCURRENT_STREAMS, CID),
    true;
maybe_maximize_mcs(_CID, Status, MCSChanged) when Status =:= changed orelse
                                                  Status =:= cached ->
    MCSChanged.

%%--------------------------------------------------------------------
change_MCS(MCS, ConnPid) ->
    Settings = #settings{max_concurrent_streams=MCS},
    try h2_connection:update_settings(ConnPid, Settings) of
        Resp ->
            Resp
    catch
        exit:{noproc, Info} ->
            lager:error("h2_connection (pid ~p) gone: ~p", [ConnPid, Info]),
            {error, connection_closed};
        exit:{timeout, Info} ->
            lager:error("h2_connection (pid ~p) timeout: ~p", [ConnPid, Info]),
            {error, timeout}
    end.

%%--------------------------------------------------------------------
get_auth_method(ConnPid) ->
    case get_and_check_peercert(ConnPid) of
        undefined ->
            {token, none};
        Cert ->
            {cert, Cert}
    end.

%%--------------------------------------------------------------------
get_and_check_peercert(ConnPid) ->
    try h2_connection:get_peercert(ConnPid) of
        {ok, PeerCertDer} ->
            PeerCert = apns_cert:der_decode_cert(PeerCertDer),
            apns_cert:get_cert_info_map(PeerCert);
        {error, _} ->
            undefined
    catch
        exit:{noproc, Info} ->
            lager:error("h2_connection (pid ~p) gone: ~p", [ConnPid, Info]),
            {error, connection_closed};
        exit:{timeout, Info} ->
            lager:error("h2_connection (pid ~p) timeout: ~p", [ConnPid, Info]),
            {error, timeout}
    end.

%%--------------------------------------------------------------------
handle_request(Method, Path, #?S{stream=#stream{id=SID,
                                                conn_pid=CID}}=St) ->
    Rsp = make_response(Method, Path, St),
    lager:debug("[StrId:~B] sending response ~p", [SID, Rsp]),
    send_response(CID, SID, Rsp).

%%--------------------------------------------------------------------
-spec make_response(Method, Path, State) -> Result when
      Method :: binary(), Path :: string(), State :: state(),
      Result :: {Headers, JsonBody}, Headers :: h2_headers(),
      JsonBody :: binary().
make_response(_Method, _Path,
              #?S{rsp=#rsp{headers=Hs, data=Body}}) when Hs /= [];
                                                         Body /= <<>> ->
    {Hs, Body};
make_response(<<"POST">>, "/3/device/" ++ Token, #?S{} = State) ->
    handle_post(Token, State);
make_response(<<"POST">>, _Other, #?S{uuid_re=RE,
                                      req=#req{headers=Headers}}=S) ->
    response_from_reason('BadPath', [apns_id_hdr(Headers, RE)], S);
make_response(_, _Other, #?S{uuid_re=RE,
                             req=#req{headers=Headers}}=S) ->
    response_from_reason('MethodNotAllowed', [apns_id_hdr(Headers, RE)], S).


%%--------------------------------------------------------------------
handle_post(Token, #?S{uuid_re=RE,
                       req=#req{headers=Headers, data=Payload, map=ReqMap0},
                       stream=#stream{id=StrmId},
                       peercert=Cert}=S) ->
    lager:debug("[StrId:~B]\nReq: ~p\nCert: ~p", [StrmId, S#?S.req, Cert]),
    try
        {ok, ApnsIdHdr} = check_apns_id_hdr(Headers, RE),
        RespHdrs = [ApnsIdHdr],
        check_apns_token(Token),
        JSON = check_payload(Payload),
        APS = pv(<<"aps">>, JSON, []),
        {ok, Prio} = check_body(APS, pv(<<"apns-priority">>, Headers)),
        ReqMap = ReqMap0#{apns_priority => Prio,
                          apns_json => JSON,
                          apns_aps_dict => APS},
        lager:info("[StrId:~B]\nJSON: ~p\nReqMap: ~p", [StrmId, JSON, ReqMap]),
        handle_req_map(ReqMap, RespHdrs, S)
    catch
        error:{badmatch, Status} ->
            response_from_reason(Status, [apns_id_hdr(Headers, RE)], S);
        throw:{status_with_apns_id, {Status, IdHdr}} ->
            response_from_reason(Status, [IdHdr], S);
        throw:{status, Status} ->
            response_from_reason(Status, [apns_id_hdr(Headers, RE)], S)
    end.

%%--------------------------------------------------------------------
handle_req_map(ReqMap, RespHdrs, #?S{stream=#stream{id=StrmId}}=S) ->
    %% TODO: maybe validate the request JSON, but could be lots of work for
    %% little reward
    %% validate_aps_json(ReqMap)
    SimCfg = get_sim_cfg(ReqMap),
    {Response, Delay} = make_sim_response(SimCfg, RespHdrs, S),
    case Delay of
        Ms when is_integer(Ms), Ms =< 0 ->
            ok;
        Ms when is_integer(Ms) ->
            lager:info("[StrId:~B] Delaying for ~B ms", [StrmId, Ms]),
            sleep(Ms)
    end,
    Response.

%%--------------------------------------------------------------------
sleep(Ms) ->
    receive after Ms -> ok end.

%%--------------------------------------------------------------------
pv(K, Cfg) ->
    pv(K, Cfg, undefined).

%%--------------------------------------------------------------------
pv(K, Cfg, Default) ->
    case lists:keyfind(K, 1, Cfg) of
        {_, V} -> V;
        false  -> Default
    end.

-compile({inline, [pv/2, pv/3]}).

%%--------------------------------------------------------------------
assert_pv(Key, Props, Exception) ->
    case pv(Key, Props) of
        undefined ->
            throw(Exception);
        Value ->
            Value
    end.

%%--------------------------------------------------------------------
-define(sim_status_code(Cfg), sc_util:to_bin(pv(<<"status_code">>, Cfg, <<>>))).
-define(sim_body(Cfg), base64:decode(pv(<<"body">>, Cfg, <<>>))).
-define(sim_delay(Cfg), pv(<<"delay">>, Cfg, 0)).
-define(sim_reason(Cfg), pv(<<"reason">>, Cfg, <<>>)).

-define(dbg_msg(Fmt, Args), lager:info(Fmt, Args)).

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

    ?dbg_msg("\n"
             "StatusCode = ~p\n"
             "Reason = ~p\n"
             "Body = ~p\n"
             "Delay = ~p\n",
             [StatusCode, Reason, Body, Delay]),

    {StsHdr, BodyOverride} = get_sim_sts_body(StatusCode, Reason, S),
    ?dbg_msg("\n"
             "StsHdr = ~p\n"
             "BodyOverride = ~p\n",
             [StsHdr, BodyOverride]),

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

-compile({inline, [get_sim_sts_body/3]}).

%%--------------------------------------------------------------------
maybe_override_body(<<>>, OBody) ->
    OBody;
maybe_override_body(Body, undefined) ->
    Body;
maybe_override_body(_Body, OBody) ->
    OBody.

-compile({inline, [maybe_override_body/2]}).

%%--------------------------------------------------------------------
get_sim_cfg(#{apns_json := JSON}) ->
    pv(<<"sim_cfg">>, JSON, []).

-compile({inline, [get_sim_cfg/1]}).

%%--------------------------------------------------------------------
send_response(ConnPid, StrmId, {Headers, Body}) ->
    {Opts, SendBody} = send_opts(Body),
    lager:debug("[StrId:~B] Sending headers:\n~p", [StrmId, Headers]),
    h2_connection:send_headers(ConnPid, StrmId, Headers, Opts),
    send_body(ConnPid, StrmId, SendBody, Body).

%%--------------------------------------------------------------------
send_body(ConnPid, StrmId, true, Body) ->
    lager:debug("[StrId:~B] Sending body:\n~p", [StrmId, Body]),
    h2_connection:send_body(ConnPid, StrmId, Body);
send_body(_ConnPid, StrmId, false, Body) ->
    lager:debug("[StrId:~B] NOT sending body=~p", [StrmId, Body]).

%%--------------------------------------------------------------------
send_opts(undefined) ->
    {[{send_end_stream, true}], false};
send_opts(_) ->
    {[], true}.

%%--------------------------------------------------------------------
-spec apns_id_hdr(Headers, RE) -> Result when
      Headers :: h2_headers(), RE :: re:mp(), Result :: h2_header().
apns_id_hdr(Headers, RE) ->
    {_, Hdr} = check_apns_id_hdr(Headers, RE),
    Hdr.

%%--------------------------------------------------------------------
-spec check_apns_id_hdr(Headers, RE) -> Result when
      Headers :: h2_headers(), RE :: re:mp(),
      Result :: {ok | 'BadMessageId', h2_header()}.
check_apns_id_hdr(Headers, RE) ->
    case lists:keyfind(<<"apns-id">>, 1, Headers) of
        {<<"apns-id">>, UUID} = Hdr ->
            case re:run(binary_to_list(UUID), RE, [{capture, none}]) of
                match ->
                    {ok, Hdr};
                nomatch ->
                    {'BadMessageId', Hdr}
            end;
        false ->
            {ok, make_apns_id_hdr()}
    end.

%%--------------------------------------------------------------------
make_apns_id_hdr() ->
    {<<"apns-id">>, list_to_binary(
                      string:to_upper(
                        binary_to_list(apns_lib_http2:make_uuid())
                       )
                     )
    }.

-compile({inline, [make_apns_id_hdr/0]}).

%%--------------------------------------------------------------------
-spec check_headers(Headers, Cert, RE) -> Result when
      Headers :: h2_headers(), Cert :: undefined | map(), RE :: re:mp(),
      Result :: map().
check_headers(Headers, Cert, RE) ->
    %RespHdrs = [apns_id_hdr(Headers)],
    Topic0 = pv(<<"apns-topic">>, Headers),
    {Topic, App} = check_topic(Topic0, Cert),
    UUID = apns_id_hdr(Headers, RE),
    Exp0 = pv(<<"apns-expiration">>, Headers),
    {ok, Exp} = check_expiration(Exp0),

    #{apns_topic => Topic,
      apns_expiration => Exp,
      apns_id => UUID,
      cert_app => App}.

%%--------------------------------------------------------------------
-spec check_body(APS, Prio) -> Result when
      APS :: jsx:json_term(), Prio :: undefined | non_neg_integer(),
      Result :: {ok, Priority},
      Priority :: non_neg_integer().
check_body(APS, Prio) ->
    ContentAvailable = pv(<<"content-available">>, APS),
    Count = length(APS),
    check_priority(Prio, ContentAvailable, Count).

%%--------------------------------------------------------------------
check_apns_token(Token) ->
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
%% Verify the JWT
%%--------------------------------------------------------------------
-spec check_jwt_auth(Headers) -> Result when
      Headers :: h2_headers(),
      Result :: {ok, {cached | changed, JWT}}
              | {error, Status}
              | no_auth_header,
      JWT :: binary(), Status :: atom().
check_jwt_auth(Headers) ->
    case pv(<<"authorization">>, Headers) of
        undefined ->
            no_auth_header;
        Auth ->
            Topic = assert_pv(<<"apns-topic">>, Headers,
                              {status, 'MissingTopic'}),
            JWT = extract_auth_token(Auth),
            case apns_erl_sim_auth_cache:validate_jwt(JWT) of
                ok -> % JWT has not expired and is bitwise-identical to
                      % last good JWT
                    {ok, {cached, JWT}};
                {error, _} ->
                    decode_and_verify_jwt(JWT, Topic)
            end
    end.

%%--------------------------------------------------------------------
decode_and_verify_jwt(JWT, Topic) ->
    case apns_jwt:decode_jwt(JWT) of
        {error, Reason} = Error ->
            lager:error("Error decoding jwt: ~p", [Reason]),
            Error;
        DecodedJWT ->
            case verify_jwt(DecodedJWT, Topic) of
                ok ->
                    apns_erl_sim_auth_cache:add_auth({jwt, JWT, ?JWT_EXPIRY}),
                    {ok, {changed, JWT}};
                {error, Status}=Error when is_atom(Status) ->
                    Error
            end
    end.

%%--------------------------------------------------------------------
extract_auth_token(<<BBearer:6/binary, $\s, JWT/binary>>) ->
    case string:to_lower(binary_to_list(BBearer)) of
        "bearer" ->
             JWT;
        _ ->
            throw({status, 'InvalidProviderToken'})
    end;
extract_auth_token(_Auth) ->
    throw({status, 'InvalidProviderToken'}).

%%--------------------------------------------------------------------
-spec load_key_for_jwt({Hdr, Payl, Sig, SigInput}, Topic) -> Result when
      Hdr :: jsx:json_term(), Payl :: jsx:json_term(), Sig :: binary(),
      SigInput :: binary(), Topic :: binary(),
      Result :: {Kid, Iss, PK}, Kid :: binary(), Iss :: binary(),
      PK :: ec_private_key().
load_key_for_jwt({Hdr, Payl, _, _}, Topic) ->
    Kid = assert_pv(<<"kid">>, Hdr, {status, 'InvalidProviderToken'}),
    Iss = assert_pv(<<"iss">>, Payl, {status, 'InvalidProviderToken'}),
    case apns_erl_sim:get_key(Kid, Iss, Topic) of
        {ok, Key} ->
            {Kid, Iss, Key};
        {error, jwt_key_path_undefined}=Crash ->
            lager:critical("Configuration error: jwt key path undefined"),
            erlang:exit(Crash);
        {error, _} ->
            lager:warning("Cannot load key for kid=~s, iss=~s, topic=~s",
                          [Kid, Iss, Topic]),
            throw({status, 'InvalidProviderToken'})
    end.

%%--------------------------------------------------------------------
%% @private
-spec verify_jwt({Hdr, Payl, Sig, SigInput}, Topic) -> Result when
      Hdr :: jsx:json_term(), Payl :: jsx:json_term(), Sig :: binary(),
      SigInput :: binary(), Topic :: binary(),
      Result :: ok
              | {error, 'InvalidProviderToken'}
              | {error, 'ExpiredProviderToken'}.
verify_jwt({_Hdr, _Payl, _Sig, _SigInput}=DecodedJWT, <<Topic/binary>>) ->
    {Kid, Iss, Key} = load_key_for_jwt(DecodedJWT, Topic),
    Ctx = apns_jwt:new(Kid, Iss, Key),
    case apns_jwt:verify_jwt(DecodedJWT, Ctx) of
        ok ->
            ok;
        {error, Error} ->
            lager:error("Error verifying jwt: ~p", [Error]),
            convert_verify_jwt_error(Error)
    end.

%%--------------------------------------------------------------------
%% @private
convert_verify_jwt_error({missing_keys, [_|_], bad_items, _}) ->
    {error, 'InvalidProviderToken'};
convert_verify_jwt_error({missing_keys, _, bad_items, L}) ->
    case pv(<<"iat">>, L) of
        Iat when is_integer(Iat) ->
            {error, 'ExpiredProviderToken'};
        _ ->
            {error, 'InvalidProviderToken'}
    end;
convert_verify_jwt_error(_) ->
    {error, 'InvalidProviderToken'}.

%%--------------------------------------------------------------------
-spec check_topic(ApnsTopic, CertInfo) -> Result when
      ApnsTopic :: undefined | binary(), CertInfo :: undefined | map(),
      Result :: 'BadCertificate'
              | 'InternalServerError'
              | 'MissingTopic'
              | {Topic, App},
      Topic :: binary(), App :: undefined | binary().
check_topic(undefined, undefined) ->
    'MissingTopic';
check_topic(<<ApnsTopic/binary>>, undefined) ->
    {ApnsTopic, undefined};
check_topic(ApnsTopic, #{}=CertInfo) ->
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

-compile({inline, [get_cert_topics/1]}).

%%--------------------------------------------------------------------
get_cert_subject_uid(#{subject_uid := Topic}) ->
    Topic.

-compile({inline, [get_cert_subject_uid/1]}).

%%--------------------------------------------------------------------
get_default_topic(true = _IsMultTopics, _CertSubjUid) ->
    %% No topic provided and multiple topics exist is an error
    'MissingTopic';
get_default_topic(false = _IsMultTopics, CertSubjUid) ->
    %% No topic provided and no multiple topics: use cert subject uid
    {CertSubjUid, undefined}.

-compile({inline, [get_default_topic/2]}).

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

-compile({inline, [check_content_available_key/3]}).

%%--------------------------------------------------------------------
-spec reason(Rsn, RsnMap) -> Json when
      Rsn :: atom(), RsnMap :: map(), Json :: binary().
reason(Rsn, RsnMap) when is_atom(Rsn) andalso is_map(RsnMap) ->
    maps:get(Rsn, RsnMap).

-compile({inline, [reason/2]}).

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

-compile({inline, [status_hdr/2]}).


%%--------------------------------------------------------------------
encode_status_hdr({<<":status">>, Sts} = Val, Rsn) when is_binary(Sts),
                                                        is_atom(Rsn) ->
    {Val, jsx:encode([
                      {reason, list_to_binary(atom_to_list(Rsn))}
                     ] ++ maybe_ts(Sts))}.

-compile({inline, [encode_status_hdr/2]}).

%%--------------------------------------------------------------------
maybe_ts(<<"410">>) ->
    [{timestamp, erlang:system_time(milli_seconds)}];
maybe_ts(_) ->
    [].

-compile({inline, [maybe_ts/1]}).

%%--------------------------------------------------------------------
-spec response_from_reason(ReasonName, ExtraHdrs, State)  -> Result when
      ReasonName :: atom(), ExtraHdrs :: h2_headers(), State :: state(),
      Result :: {Headers, JSON}, Headers :: h2_headers(), JSON :: binary().
response_from_reason(ReasonName, ExtraHdrs, State) when is_atom(ReasonName) ->
    {StsHdr, Reason} = status_hdr(ReasonName, State#?S.sts_hdrs),
    {[StsHdr | ExtraHdrs], Reason}.

%%--------------------------------------------------------------------
reason_for_status_code(Sts) ->
    case lists:keyfind(Sts, 2, apns_erl_sim_stream:status_list()) of
        {Reason, _} ->
            Reason;
        false ->
            'InternalServerError'
    end.

-compile({inline, [reason_for_status_code/1]}).

%%--------------------------------------------------------------------
maybe_reason(success, _) ->
    undefined;
maybe_reason(ReasonName, S) ->
    reason(ReasonName, S#?S.reasons).

-compile({inline, [maybe_reason/2]}).

%%--------------------------------------------------------------------
-spec reasons() -> map().
reasons() ->
    maps:from_list([{b2a(B), jsx:encode([{reason, B}])} || B <- reason_list()]).

%%--------------------------------------------------------------------
reason_list() ->
    [
     <<"BadCertificate">>,
     <<"BadCertificateEnvironment">>,
     <<"BadCollapseId">>,
     <<"BadDeviceToken">>,
     <<"BadExpirationDate">>,
     <<"BadMessageId">>,
     <<"BadPath">>,
     <<"BadPriority">>,
     <<"BadTopic">>,
     <<"DeviceTokenNotForTopic">>,
     <<"DuplicateHeaders">>,
     <<"ExpiredProviderToken">>,
     <<"Forbidden">>,
     <<"IdleTimeout">>,
     <<"InternalServerError">>,
     <<"InvalidProviderToken">>,
     <<"MethodNotAllowed">>,
     <<"MissingDeviceToken">>,
     <<"MissingProviderToken">>,
     <<"MissingTopic">>,
     <<"PayloadEmpty">>,
     <<"PayloadTooLarge">>,
     <<"ServiceUnavailable">>,
     <<"Shutdown">>,
     <<"TooManyProviderTokenUpdates">>,
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
     {'BadCollapseId',                  <<"400">>},
     {'BadDeviceToken',                 <<"400">>},
     {'BadExpirationDate',              <<"400">>},
     {'BadMessageId',                   <<"400">>},
     {'BadPriority',                    <<"400">>},
     {'BadTopic',                       <<"400">>},
     {'DeviceTokenNotForTopic',         <<"400">>},
     {'DuplicateHeaders',               <<"400">>},
     {'IdleTimeout',                    <<"400">>},
     {'MissingDeviceToken',             <<"400">>},
     {'MissingTopic',                   <<"400">>},
     {'PayloadEmpty',                   <<"400">>},
     {'TopicDisallowed',                <<"400">>},

     {'BadCertificate',                 <<"403">>},
     {'BadCertificateEnvironment',      <<"403">>},
     {'ExpiredProviderToken',           <<"403">>},
     {'Forbidden',                      <<"403">>},
     {'InvalidProviderToken',           <<"403">>},
     {'MissingProviderToken',           <<"403">>},

     {'BadPath',                        <<"404">>},

     {'MethodNotAllowed',               <<"405">>},

     {'Unregistered',                   <<"410">>},

     {'PayloadTooLarge',                <<"413">>},

     {'TooManyProviderTokenUpdates',    <<"429">>},
     {'TooManyRequests',                <<"429">>},

     {'InternalServerError',            <<"500">>},

     {'ServiceUnavailable',             <<"503">>},
     {'Shutdown',                       <<"503">>},

     {success,                          <<"200">>}
    ].


%%--------------------------------------------------------------------
b2a(<<B/binary>>) ->
    list_to_atom(binary_to_list(B)).

-compile({inline, [b2a/1]}).

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

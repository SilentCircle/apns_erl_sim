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
%%% @author Edwin Fine
%%% @copyright (C) 2016, Silent Circle LLC
%%% @doc
%%%
%%% @end
%%% Created : 2016-08-17 16:02:26.546440
%%%-------------------------------------------------------------------
-module(apns_erl_sim).

-behaviour(gen_server).

%%%===================================================================
%%% Includes
%%%===================================================================
-include_lib("kernel/include/file.hrl").
-include_lib("lager/include/lager.hrl").
-include_lib("chatterbox/include/http2.hrl").

%% API
-export([
         start_link/1,
         settings/0,
         get_key/3
        ]).

%% gen_server callbacks
-export([
         init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-type terminate_reason() :: normal |
                            shutdown |
                            {shutdown, term()} |
                            term().

-define(S, ?MODULE).

-type key_id() :: binary().
-type key_value() :: term().

-record(?S, {
           jwt_key_path = undefined     :: undefined | string(),
           private_keys = []            :: [{key_id(), key_value()}]
          }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link(Args) -> Result when
      Args :: list(), Result :: {ok, pid()} | ignore | {error, term()}.
start_link(Args) when is_list(Args) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Args], []).

%%--------------------------------------------------------------------
%% @doc
%% Return opaque HTTP/2 settings.
%% @end
%%--------------------------------------------------------------------
-spec settings() -> term().
settings() ->
    %% Start off with MCS == 1 until authenticated
    application:set_env(chatterbox, server_max_concurrent_streams, 1),
    chatterbox:settings(server).

%%--------------------------------------------------------------------
%% @doc
%% Get contents of signing key file corresponding to `Kid', `Iss', and `Topic'.
%% File MUST be named `APNsAuthKey_<TeamID>_<BundleID>_<KeyID>.p8',
%% where `TeamID' corresponds to `Iss', `BundleID' corresponds to
%% `Topic', and `KeyID' corresponds to `Kid'.
%%
%% The files must be in a directory whose name is in the `apns_erl_sim'
%% environment as `{jwt_key_path, string()}'.
%%
%% Return `{ok, ContentsOfKeyfile :: binary()}' on success, `{error, term()}'
%% on failure.
%% @end
%%--------------------------------------------------------------------
-spec get_key(Kid, Iss, Topic) -> Result when
      Kid :: binary(), Iss :: binary(), Topic :: binary(),
      Result :: {ok, FileData :: binary()} | {error, term()}.
get_key(<<Kid/binary>>, <<Iss/binary>>, <<Topic/binary>>) ->
    gen_server:call(?SERVER, {get_key, {Kid, Iss, Topic}}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init(term()) -> {ok, State::term()} |
                      {ok, State::term(), Timeout::timeout()} |
                      {ok, State::term(), 'hibernate'} |
                      {stop, Reason::term()} |
                      'ignore'
                      .
init([Props]=Args) ->
    lager:debug("Args: ~p", [Args]),
    JWTKeyPath = sc_util:req_val(jwt_key_path, Props),
    {ok, #?S{jwt_key_path=JWTKeyPath}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request::term(),
                  From::{pid(), Tag::term()},
                  State::term()) ->
    {reply, Reply::term(), NewState::term()} |
    {reply, Reply::term(), NewState::term(), Timeout::timeout()} |
    {reply, Reply::term(), NewState::term(), 'hibernate'} |
    {noreply, NewState::term()} |
    {noreply, NewState::term(), 'hibernate'} |
    {noreply, NewState::term(), Timeout::timeout()} |
    {stop, Reason::term(), Reply::term(), NewState::term()} |
    {stop, Reason::term(), NewState::term()}
    .

handle_call({get_key, _}, _From, #?S{jwt_key_path=undefined}=S) ->
    {reply, {error, jwt_key_path_undefined}, S};
handle_call({get_key, {Kid, Iss, Topic}}, _From,
            #?S{private_keys=Ks0}=State) ->
    case get_key_impl(Kid, Iss, Topic, State#?S.jwt_key_path, Ks0) of
        {ok, {cached, Key}} ->
            {reply, {ok, Key}, State};
        {ok, Key}=Reply ->
            Ks = lists:keystore(Kid, 1, Ks0, {Kid, Key}),
            {reply, Reply, State#?S{private_keys=Ks}};
        {error, _}=Error ->
            {reply, Error, State}
    end;
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
-spec handle_cast(Request::term(),
                  State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), 'hibernate'} |
    {noreply, NewState::term(), Timeout::timeout()} |
    {stop, Reason::term(), NewState::term()}
    .

handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Request::term(),
                  State::term()) ->
    {noreply, NewState::term()} |
    {noreply, NewState::term(), 'hibernate'} |
    {noreply, NewState::term(), Timeout::timeout()} |
    {stop, Reason::term(), NewState::term()}
    .
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
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason::terminate_reason(),
                State::term()) -> no_return().
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn::term() | {down, term()},
                  State::term(),
                  Extra::term()) ->
    {ok, NewState::term()} |
    {error, Reason::term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%%--------------------------------------------------------------------
get_key_impl(Kid, Iss, Topic, JwtKeyPath, Ks) ->
    case lists:keyfind(Kid, 1, Ks) of
        {Kid, Key} ->
            {ok, {cached, Key}};
        false ->
            get_key_from_file(Kid, Iss, Topic, JwtKeyPath)
    end.

%%--------------------------------------------------------------------
get_key_from_file(Kid, Iss, Topic, JwtKeyPath) ->
    case check_path(JwtKeyPath) of
        ok ->
            Path = make_keyfile_path(Kid, Iss, Topic, JwtKeyPath),
            get_key_from_path(Path);
        {error, _Reason} = Error ->
            Error
    end.

%%--------------------------------------------------------------------
get_key_from_path(Path) ->
    case file:read_file(Path) of
        {ok, Pem} ->
            pem_to_key(Pem);
        {error,_}=Error ->
            Error
    end.

%%--------------------------------------------------------------------
pem_to_key(Pem) ->
    try apns_jwt:get_private_key(Pem) of
        Key ->
            {ok, Key}
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

%%--------------------------------------------------------------------
make_keyfile_path(Kid, Iss, Topic, Path) ->
    Filename = list_to_binary(["APNsAuthKey_", Iss, $_, Topic,
                               $_, Kid, ".p8"]),
    filename:join(Path, binary_to_list(Filename)).

%%--------------------------------------------------------------------
check_path(Path) ->
    case file:read_file_info(Path) of
        {ok, #file_info{}=FI} ->
            case {FI#file_info.type, FI#file_info.access} of
                {directory, A} when A =:= read; A =:= read_write ->
                    ok;
                {directory, _} ->
                    {error, no_read_access};
                {_NotDir, _DontCare} ->
                    {error, not_a_directory}
            end;
        {error, _Reason} = Error ->
            Error
    end.


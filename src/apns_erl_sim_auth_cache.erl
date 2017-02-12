%%%-------------------------------------------------------------------
%%% @author Edwin Fine
%%% @copyright (C) 2017, Silent Circle LLC
%%% @doc Cache of authorization info.
%%% This caches JWTs and APNS certificate data.
%%% @end
%%%-------------------------------------------------------------------
-module(apns_erl_sim_auth_cache).
-behaviour(gen_server).

%%%====================================================================
%%% Includes
%%%====================================================================
-include_lib("lager/include/lager.hrl").

%% API
-export([
         start_link/0,
         add_auth/1,
         add_auth/2,
         get_cert/0,
         get_cert/1,
         remove_auth/0,
         remove_auth/1,
         validate_jwt/1,
         validate_jwt/2
        ]).

%%%====================================================================
%%% Behaviour exports
%%%====================================================================
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%%====================================================================
%%% Defines
%%%====================================================================
-define(SERVER, ?MODULE).
-define(S, ?MODULE).

%%%====================================================================
%%% Records and types
%%%====================================================================
-type terminate_reason() :: normal |
                            shutdown |
                            {shutdown, term()} |
                            term().

-record(?S, {
           tid :: non_neg_integer(),
           mon_procs = []
          }).

-record(jwt_info, {
          exp :: integer(), % Expiry time in POSIX secs
          jwt :: binary()   % The last authed JWT
         }).
-type jwt_info() :: #jwt_info{}.

-record(cert_info, {
          map :: map()
         }).

-type cert_info() :: #cert_info{}.

-record(auth, {
          pid :: pid(),     % Connection that has authed the JWT
          info :: jwt_info() | cert_info()
         }).

-type jwt() :: binary().
-type expiry() :: non_neg_integer().
-type cert() :: map().

-type jwt_data() :: {jwt, jwt(), expiry()}.
-type cert_data() :: {cert, cert()}.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Start the server.
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @equiv add_auth(self(), {jwt, JWT, Expiry})
%% @end
%%--------------------------------------------------------------------
-spec add_auth(AuthData) -> Result when
      AuthData :: jwt_data() | cert_data(), Result :: ok.
add_auth({jwt, _JWT, _Expiry}=AuthData) ->
    add_auth(self(), AuthData).

%%--------------------------------------------------------------------
%% @doc
%% Add auth information.
%%
%% Auth information may be either
%%
%% <ul>
%%   <li>A validated JWT with a lifetime of POSIX secs after its `iat' (Issued
%%   At time). In other words, `Expiry' is the number of seconds for which the
%%   JWT is considered valid. If `Expiry' is zero, the JWT will simply be
%%   discarded.</li>
%%   <li>An APNS certificate in map format, as returned by
%%   apns_cert:get_cert_info_map/1.</li>
%% </ul>
%%
%% `Pid' will be monitored, and if the process dies, its entry will be
%% removed from the table. `Pid' cannot have both an APNS cert and a
%% JWT entry, since they are mutually exclusive in APNS (any token-
%% based authentication is ignored if there is valid certificate-based
%% authentication).
%% @end
%%--------------------------------------------------------------------
-spec add_auth(Pid, AuthData) -> Result when
      Pid :: pid(), AuthData :: jwt_data() | cert_data(), Result :: ok.
add_auth(Pid, {jwt, <<_JWT/binary>>, Expiry}=Auth) when is_pid(Pid),
                                                        is_integer(Expiry),
                                                        Expiry >= 0 ->
    gen_server:cast(?SERVER, {add_auth, Pid, Auth});
add_auth(Pid, {cert, #{}=_CertMap}=Auth) when is_pid(Pid) ->
    gen_server:cast(?SERVER, {add_auth, Pid, Auth}).

%%--------------------------------------------------------------------
%% @equiv get_cert(self())
%% @end
%%--------------------------------------------------------------------
-spec get_cert() -> Result when
      Result :: map() | {error, not_found}.
get_cert() ->
    get_cert(self()).

%%--------------------------------------------------------------------
%% @doc
%% Retrieve an APNS certificate by pid.
%% @end
%%--------------------------------------------------------------------
-spec get_cert(Pid) -> Result when
      Pid :: pid(), Result :: map() | {error, not_found}.
get_cert(Pid) when is_pid(Pid) ->
    gen_server:call(?SERVER, {get_cert, Pid}).

%%--------------------------------------------------------------------
%% @equiv validate_jwt(self(), JWT)
%% @end
%%--------------------------------------------------------------------
-spec validate_jwt(JWT) -> Result when
      JWT :: binary(), Result :: ok | {error, expired | changed | not_found}.
validate_jwt(JWT) ->
    validate_jwt(self(), JWT).

%%--------------------------------------------------------------------
%% @doc
%% Validate a JWT by looking it up by pid and bitwise-comparing it
%% to a stored JWT. The JWT will be valid iff:
%%
%% <ul>
%%  <li>It is found in the cache;</li>
%%  <li>The cached version has not expired;</li>
%%  <li>It is bitwise identical to the cached version</li>
%% </ul>
%%
%% If the JWT is expired, it will be flushed from the cache.
%% @end
%%--------------------------------------------------------------------
-spec validate_jwt(Pid, JWT) -> Result when
      Pid :: pid(), JWT :: binary(),
      Result :: ok | {error, expired | changed | not_found}.
validate_jwt(Pid, <<JWT/binary>>) when is_pid(Pid) ->
    gen_server:call(?SERVER, {validate_jwt, Pid, JWT}).

%%--------------------------------------------------------------------
%% @equiv remove_auth(self())
%% @end
%%--------------------------------------------------------------------
-spec remove_auth() -> ok.
remove_auth() ->
    remove_auth(self()).

%%--------------------------------------------------------------------
%% @doc
%% Remove auth item corresponding to `Pid'.
%% @end
%%--------------------------------------------------------------------
-spec remove_auth(Pid) -> ok when Pid :: pid().
remove_auth(Pid) when is_pid(Pid) ->
    gen_server:cast(?SERVER, {remove_auth, Pid}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initialize the server.
%% @end
%%--------------------------------------------------------------------
-spec init(term()) -> {ok, State::term()} |
                      {ok, State::term(), Timeout::timeout()} |
                      {ok, State::term(), 'hibernate'} |
                      {stop, Reason::term()} |
                      'ignore'
                      .
init([]) ->
    {ok, #?S{tid=ets:new(?MODULE, [{keypos, #auth.pid}])}}.

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

handle_call({validate_jwt, Pid, Jwt}, _From, State) ->
    {reply, validate_jwt_impl(State#?S.tid, Pid, Jwt), State};
handle_call({get_cert, Pid}, _From, State) ->
    {reply, get_cert_impl(State#?S.tid, Pid), State};
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

handle_cast({remove_auth, Pid}, State) ->
    MPs = remove_auth_impl(State#?S.tid, Pid, State#?S.mon_procs),
    {noreply, State#?S{mon_procs=MPs}};
handle_cast({add_auth, {_Pid, {jwt, _JWT, 0}}}, State) ->
    {noreply, State};
handle_cast({add_auth, {_Pid, {cert, undefined}}}, State) ->
    {noreply, State};
handle_cast({add_auth, {Pid, {jwt, _JWT, _ExpSecs}=Auth}}, St) ->
    MPs = add_auth_impl(St#?S.tid, {Pid, Auth}, St#?S.mon_procs),
    {noreply, St#?S{mon_procs=MPs}};
handle_cast({add_auth, {Pid, {cert, _Map}=Auth}}, St) ->
    MPs = add_auth_impl(St#?S.tid, {Pid, Auth}, St#?S.mon_procs),
    {noreply, St#?S{mon_procs=MPs}};
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
handle_info({'DOWN', _Ref, process, Pid, _Info}, State) when is_pid(Pid) ->
    ets:delete(State#?S.tid, Pid),
    lager:debug("Process died, pid ~p, reason ~p", [Pid, _Info]),
    {noreply, State};
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
%% Implementations
%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
add_auth_impl(Tid, {Pid, {jwt, <<JWT/binary>>, ExpSecs}}, MPs0) ->
    case calc_expiry(ExpSecs, JWT) of
        {ok, Expiry} ->
            true = ets:insert(Tid, #auth{pid=Pid,
                                         info=#jwt_info{jwt=JWT,
                                                        exp=Expiry}}),
            lager:debug("Added JWT for pid ~p with expiry ~p: ~p",
                        [Pid, Expiry, JWT]),
            maybe_monitor(Pid, MPs0);
        Error ->
            lager:error("calc_expiry returned error ~p", [Error]),
            MPs0
    end;
add_auth_impl(Tid, {Pid, {cert, #{}=Cert}}, MPs0) ->
    true = ets:insert(Tid, #auth{pid=Pid,
                                 info=#cert_info{map=Cert}}),
    lager:debug("Added cert for pid ~p: ~p", [Pid, Cert]),
    maybe_monitor(Pid, MPs0).

%%--------------------------------------------------------------------
remove_auth_impl(Tid, Pid, MPs0) ->
    true = ets:delete(Tid, Pid),
    case lists:keytake(Pid, 1, MPs0) of
        {value, {_Pid, Ref}, MPs} ->
            true = erlang:demonitor(Ref),
            lager:debug("Demonitored ~p", [Pid]),
            MPs;
        false ->
            MPs0
    end.

%%--------------------------------------------------------------------
validate_jwt_impl(Tid, Pid, <<JWT/binary>>) ->
    case ets:lookup(Tid, Pid) of
        [#auth{info=#jwt_info{exp=Exp, jwt=ValidJWT}}] ->
            case Exp > erlang:system_time(seconds) of
                true ->
                    case JWT =:= ValidJWT of
                        true -> ok;
                        false -> {error, changed}
                    end;
                false ->
                    ets:delete(Tid, Pid),
                    {error, expired}
            end;
        [#auth{info=#cert_info{}}] ->
            {error, not_found};
        [] ->
            {error, not_found}
    end.

%%--------------------------------------------------------------------
get_cert_impl(Tid, Pid) ->
    case ets:lookup(Tid, Pid) of
        [#auth{info=#cert_info{map=Map}}] ->
            Map;
        [#auth{info=#jwt_info{}}] ->
            {error, not_found};
        [] ->
            {error, not_found}
    end.

%%--------------------------------------------------------------------
%% Helper functions
%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
-spec calc_expiry(Expiry, JWT) -> Result when
      Expiry :: pos_integer(), JWT :: binary(), Result :: {ok, Exp} | Error,
      Exp :: pos_integer(), Error :: {term(), term()}.
calc_expiry(Expiry, JWT) ->
    DecodedJWT = try apns_jwt:decode_jwt(JWT)
                 catch
                     What:Why ->
                         {What, Why}
                 end,

    case DecodedJWT of
        {_Hdr, Payload, _Sig, _SigInput} ->
            case proplists:get_value(<<"iat">>, Payload) of
                undefined ->
                    {error, missing_iat};
                Iat when is_integer(Iat) ->
                    {ok, Iat + Expiry};
                _ ->
                    {error, invalid_iat}
            end;
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
maybe_monitor(Pid, MPs0) ->
    case lists:keymember(Pid, 1, MPs0) of
        true ->
            MPs0; % Already monitored
        false ->
            Ref = erlang:monitor(process, Pid),
            lager:debug("Monitored pid ~p with ref ~p",
                        [Pid, Ref]),
            [{Pid, Ref}|MPs0]
    end.


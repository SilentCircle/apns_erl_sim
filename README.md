

# Apple Push Notification Service HTTP/2 simulator. #

Copyright (c) 2016 Silent Circle, LLC.

__Version:__ 0.9.0

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

This application is an HTTP/2 simulator for APNS push.

The simulator tries very hard to behave like Apple's HTTP/2 push service,
at least as of this writing. It doesn't throttle requests (yet), but its
responses look a lot like the real thing.

It also allows the tester to control the response to a push notification POST
via keys in the notification JSON. This is easy to do without risking behavioral
issues, since APNS allows user-defined JSON outside of the `aps` dictionary.


#### <a name="Running">Running</a> ####

`apns_erl_sim` is intended to be integrated with test cases by starting it in
a different node as an application.

However, you can run it from the command line using `make run`. This starts
it in an Erlang shell and is identical to calling `rebar3 shell`.


#### <a name="Configuration">Configuration</a> ####

By default, it is configured to listen on IPv4 address `0.0.0.0:2197`. The
configuration is in `config/sys.config`. Because the simulator uses
[`chatterbox`](https://github.com/joedevivo/chatterbox.git) for HTTP/2,
the configuration sets up `chatterbox` something like this:

```
  {chatterbox,
   [
    {ssl, true},
    {ssl_options, [{port,       2197},
                   {certfile,   "com.apple.push.api.cert.pem"},
                   {keyfile,    "com.apple.push.api.key.unencrypted.pem"},
                   {cacertfile, "FakeAppleAllCAChain.cert.pem"},
                   {honor_cipher_order, false},
                   {fail_if_no_peer_cert, true},
                   {verify, verify_peer},
                   {versions, ['tlsv1.2']},
                   {alpn_preferred_protocols, [<<"h2">>]}]}
   ]}
```

It's recommended that only `port`, `certfile`, `keyfile`, or `cacertfile` be
changed.


#### <a name="Fake_certificates">Fake certificates</a> ####

`cacertfile`, `certfile`, and `keyfile` are fake Apple certificates generated
by a script in the [`apns_tools`](https://github.com/SilentCircle/apns_tools.git) github
repository.
`apns_tools/fake_apple_certs.sh` generates an entire fake Apple Push PKI infrastructure.

To use this simulator, you'll need to use `fake_apple_certs.sh` to generate your own
fake certificates - both for the simulator and for whatever push client uses it.
A great way to do this is to generate the certs every time you run your test cases,
and put them somewhere that both the simulator and the test code and get to them.
This avoids expiry and other issues, and takes only a few extra seconds of runtime.


#### <a name="Simulator_Configuration_JSON">Simulator Configuration JSON</a> ####

The JSON is a dictionary at the top level of the notification, named
`"sim_cfg"`.

<h5><a name="Example">Example</a></h5>

```
{
    "aps": {
        "alert": "blah"
    },
    "sim_cfg": {
        "status_code": 200,
        "body": "eyJyZWFzb24iOiJCYWRQcmlvcml0eSJ9",
        "delay": 5000,
        "reason": "BadPriority"
    }
}
```


<table>
<tr><th>Key</th><th>Description</th>
</tr>
<tr><td><code>"status_code"</code></td><td>
    HTTP status code, e.g. 200; omit for 200</td>
</tr>
<tr><td><code>"body"</code></td><td>Base-64 encoded JSON return value; omit for empty body</td>
</tr>
<tr><td><code>"delay"</code></td><td>Delay before responding, in ms; omit for no delay</td>
</tr>
<tr><td><code>"reason"</code></td><td>
    One of the reason strings, such as <code>PayloadEmpty</code>.  If <code>"status_code"</code> is
    omitted, a 4xx status code will be returned.</td>
</tr>
</table>



#### <a name="Document_Building">Document Building</a> ####

This uses `edown` to build markdown documents from `edoc`.  There is some
special code in `rebar.config.script` to support obtaining the version from the
`APP_VERSION` file and making it available to edoc via the `@version` macro.

See `rebar.config.script` for usage and behavior.


#### <a name="TODO">TODO</a> ####
- Use `apns_tools` to auto-generate certificates to be used by `make run`, instead
  of using the certificates in `config/`, which will eventually expire.


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/feature/handle-auth-tokens/doc/apns_erl_sim.md" class="module">apns_erl_sim</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/feature/handle-auth-tokens/doc/apns_erl_sim_app.md" class="module">apns_erl_sim_app</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/feature/handle-auth-tokens/doc/apns_erl_sim_auth_cache.md" class="module">apns_erl_sim_auth_cache</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/feature/handle-auth-tokens/doc/apns_erl_sim_stream.md" class="module">apns_erl_sim_stream</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/feature/handle-auth-tokens/doc/apns_erl_sim_sup.md" class="module">apns_erl_sim_sup</a></td></tr></table>


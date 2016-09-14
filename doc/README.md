

# Apple Push Notification Service HTTP/2 simulator. #

Copyright (c) 2016 Silent Circle, LLC.

__Version:__ 0.0.1

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

This application is an HTTP/2 simulator for APNS push.

The simulator tries very hard to behave like Apple's HTTP/2 push service,
at least as of this writing. It doesn't throttle requests (yet), but its
responses look a lot like the real thing.

It also allows the tester to control the response to a push notification POST
via keys in the notification JSON. This is easy to do without risking behavioral
issues, since APNS allows user-defined JSON outside of the `aps` dictionary.


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


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="apns_erl_sim.md" class="module">apns_erl_sim</a></td></tr>
<tr><td><a href="apns_erl_sim_app.md" class="module">apns_erl_sim_app</a></td></tr>
<tr><td><a href="apns_erl_sim_stream.md" class="module">apns_erl_sim_stream</a></td></tr>
<tr><td><a href="apns_erl_sim_sup.md" class="module">apns_erl_sim_sup</a></td></tr></table>


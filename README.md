

# Apple Push Notification Service HTTP/2 simulator. #

Copyright (c) 2016 Silent Circle, LLC.

__Version:__ Aug 17 2016 20:35:45

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

This application is an HTTP/2 simulator for APNS push.

It allows the tester to control the response to a push notification POST via
custom HTTP/2 headers.


#### <a name="Header_Values">Header Values</a> ####


<table>
<tr><th>Header</th><th>Description</th>
</tr>
<tr><td>X-ApnsTester-StatusCode</td><td>
    HTTP status code, e.g. 200; omit for 200</td>
</tr>
<tr><td>X-ApnsTester-Body</td><td>Base-64 encoded JSON return value; omit for empty body</td>
</tr>
<tr><td>X-ApnsTester-Delay</td><td>Delay before responding, in ms; Omit for no delay</td>
</tr>
<tr><td>X-ApnsTester-Reason</td><td>
    One of the reason strings, such as <code>PayloadEmpty</code>.
    If X-ApnsTester-StatusCode is omitted, a 4xx status
    code will be returned.</td>
</tr>
</table>



#### <a name="Document_Building">Document Building</a> ####

This uses `edown` to build markdown documents from `edoc`.  There is some
special code in `rebar.config.script` to support obtaining the version from the
`APP_CONFIG` file and making it available to edoc via the `@version` macro.

See `rebar.config.script` for usage and behavior.


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/master/doc/apns_erl_sim.md" class="module">apns_erl_sim</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/master/doc/apns_erl_sim_app.md" class="module">apns_erl_sim_app</a></td></tr>
<tr><td><a href="http://github.com/SilentCircle/apns_erl_sim/blob/master/doc/apns_erl_sim_sup.md" class="module">apns_erl_sim_sup</a></td></tr></table>


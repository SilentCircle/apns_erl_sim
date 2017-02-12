

# Module apns_erl_sim #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)

.

Copyright (c) (C) 2016, Silent Circle LLC

__Behaviours:__ [`gen_server`](gen_server.md).

__Authors:__ Edwin Fine.

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#get_key-3">get_key/3</a></td><td>
Get contents of signing key file corresponding to <code>Kid</code>, <code>Iss</code>, and <code>Topic</code>.</td></tr><tr><td valign="top"><a href="#settings-0">settings/0</a></td><td>
Return opaque HTTP/2 settings.</td></tr><tr><td valign="top"><a href="#start_link-1">start_link/1</a></td><td>
Starts the server.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="get_key-3"></a>

### get_key/3 ###

<pre><code>
get_key(Kid, Iss, Topic) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Kid = binary()</code></li><li><code>Iss = binary()</code></li><li><code>Topic = binary()</code></li><li><code>Result = {ok, FileData::binary()} | {error, term()}</code></li></ul>

Get contents of signing key file corresponding to `Kid`, `Iss`, and `Topic`.
File MUST be named `APNsAuthKey_<TeamID>_<BundleID>_<KeyID>.p8`,
where `TeamID` corresponds to `Iss`, `BundleID` corresponds to
`Topic`, and `KeyID` corresponds to `Kid`.

The files must be in a directory whose name is in the `apns_erl_sim`
environment as `{jwt_key_path, string()}`.

Return `{ok, ContentsOfKeyfile :: binary()}` on success, `{error, term()}`
on failure.

<a name="settings-0"></a>

### settings/0 ###

<pre><code>
settings() -&gt; term()
</code></pre>
<br />

Return opaque HTTP/2 settings.

<a name="start_link-1"></a>

### start_link/1 ###

<pre><code>
start_link(Args) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Args = list()</code></li><li><code>Result = {ok, pid()} | ignore | {error, term()}</code></li></ul>

Starts the server


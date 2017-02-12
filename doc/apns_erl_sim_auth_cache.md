

# Module apns_erl_sim_auth_cache #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

Cache of authorization info.

Copyright (c) (C) 2017, Silent Circle LLC

__Behaviours:__ [`gen_server`](gen_server.md).

__Authors:__ Edwin Fine.

<a name="description"></a>

## Description ##
This caches JWTs and APNS certificate data.
<a name="types"></a>

## Data Types ##




### <a name="type-cert">cert()</a> ###


<pre><code>
cert() = #{}
</code></pre>




### <a name="type-cert_data">cert_data()</a> ###


<pre><code>
cert_data() = {cert, <a href="#type-cert">cert()</a>}
</code></pre>




### <a name="type-expiry">expiry()</a> ###


<pre><code>
expiry() = non_neg_integer()
</code></pre>




### <a name="type-jwt">jwt()</a> ###


<pre><code>
jwt() = binary()
</code></pre>




### <a name="type-jwt_data">jwt_data()</a> ###


<pre><code>
jwt_data() = {jwt, <a href="#type-jwt">jwt()</a>, <a href="#type-expiry">expiry()</a>}
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#add_auth-1">add_auth/1</a></td><td>Equivalent to <a href="#add_auth-2"><tt>add_auth(self(), {jwt, JWT, Expiry})</tt></a>.</td></tr><tr><td valign="top"><a href="#add_auth-2">add_auth/2</a></td><td>
Add auth information.</td></tr><tr><td valign="top"><a href="#get_cert-0">get_cert/0</a></td><td>Equivalent to <a href="#get_cert-1"><tt>get_cert(self())</tt></a>.</td></tr><tr><td valign="top"><a href="#get_cert-1">get_cert/1</a></td><td>
Retrieve an APNS certificate by pid.</td></tr><tr><td valign="top"><a href="#remove_auth-0">remove_auth/0</a></td><td>Equivalent to <a href="#remove_auth-1"><tt>remove_auth(self())</tt></a>.</td></tr><tr><td valign="top"><a href="#remove_auth-1">remove_auth/1</a></td><td>
Remove auth item corresponding to <code>Pid</code>.</td></tr><tr><td valign="top"><a href="#start_link-0">start_link/0</a></td><td>
Start the server.</td></tr><tr><td valign="top"><a href="#validate_jwt-1">validate_jwt/1</a></td><td>Equivalent to <a href="#validate_jwt-2"><tt>validate_jwt(self(), JWT)</tt></a>.</td></tr><tr><td valign="top"><a href="#validate_jwt-2">validate_jwt/2</a></td><td>
Validate a JWT by looking it up by pid and bitwise-comparing it
to a stored JWT.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="add_auth-1"></a>

### add_auth/1 ###

<pre><code>
add_auth(AuthData) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>AuthData = <a href="#type-jwt_data">jwt_data()</a> | <a href="#type-cert_data">cert_data()</a></code></li><li><code>Result = ok</code></li></ul>

Equivalent to [`add_auth(self(), {jwt, JWT, Expiry})`](#add_auth-2).

<a name="add_auth-2"></a>

### add_auth/2 ###

<pre><code>
add_auth(Pid, AuthData) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Pid = pid()</code></li><li><code>AuthData = <a href="#type-jwt_data">jwt_data()</a> | <a href="#type-cert_data">cert_data()</a></code></li><li><code>Result = ok</code></li></ul>

Add auth information.

Auth information may be either

* A validated JWT with a lifetime of POSIX secs after its `iat` (Issued
At time). In other words, `Expiry` is the number of seconds for which the
JWT is considered valid. If `Expiry` is zero, the JWT will simply be
discarded.

* An APNS certificate in map format, as returned by
apns_cert:get_cert_info_map/1.


`Pid` will be monitored, and if the process dies, its entry will be
removed from the table. `Pid` cannot have both an APNS cert and a
JWT entry, since they are mutually exclusive in APNS (any token-
based authentication is ignored if there is valid certificate-based
authentication).

<a name="get_cert-0"></a>

### get_cert/0 ###

<pre><code>
get_cert() -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Result = #{} | {error, not_found}</code></li></ul>

Equivalent to [`get_cert(self())`](#get_cert-1).

<a name="get_cert-1"></a>

### get_cert/1 ###

<pre><code>
get_cert(Pid) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Pid = pid()</code></li><li><code>Result = #{} | {error, not_found}</code></li></ul>

Retrieve an APNS certificate by pid.

<a name="remove_auth-0"></a>

### remove_auth/0 ###

<pre><code>
remove_auth() -&gt; ok
</code></pre>
<br />

Equivalent to [`remove_auth(self())`](#remove_auth-1).

<a name="remove_auth-1"></a>

### remove_auth/1 ###

<pre><code>
remove_auth(Pid) -&gt; ok
</code></pre>

<ul class="definitions"><li><code>Pid = pid()</code></li></ul>

Remove auth item corresponding to `Pid`.

<a name="start_link-0"></a>

### start_link/0 ###

<pre><code>
start_link() -&gt; {ok, pid()} | ignore | {error, term()}
</code></pre>
<br />

Start the server.

<a name="validate_jwt-1"></a>

### validate_jwt/1 ###

<pre><code>
validate_jwt(JWT) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>JWT = binary()</code></li><li><code>Result = ok | {error, expired | changed | not_found}</code></li></ul>

Equivalent to [`validate_jwt(self(), JWT)`](#validate_jwt-2).

<a name="validate_jwt-2"></a>

### validate_jwt/2 ###

<pre><code>
validate_jwt(Pid, JWT) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Pid = pid()</code></li><li><code>JWT = binary()</code></li><li><code>Result = ok | {error, expired | changed | not_found}</code></li></ul>

Validate a JWT by looking it up by pid and bitwise-comparing it
to a stored JWT. The JWT will be valid iff:

* It is found in the cache;

* The cached version has not expired;

* It is bitwise identical to the cached version


If the JWT is expired, it will be flushed from the cache.




# Module apns_erl_sim_stream #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

__Behaviours:__ [`h2_stream`](h2_stream.md).

<a name="types"></a>

## Data Types ##




### <a name="type-h2_header">h2_header()</a> ###


<pre><code>
h2_header() = {binary(), binary()}
</code></pre>




### <a name="type-h2_headers">h2_headers()</a> ###


<pre><code>
h2_headers() = [<a href="#type-h2_header">h2_header()</a>]
</code></pre>




### <a name="type-state">state()</a> ###


<pre><code>
state() = #'?S'{}
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#init-2">init/2</a></td><td></td></tr><tr><td valign="top"><a href="#on_receive_request_data-2">on_receive_request_data/2</a></td><td></td></tr><tr><td valign="top"><a href="#on_receive_request_headers-2">on_receive_request_headers/2</a></td><td></td></tr><tr><td valign="top"><a href="#on_request_end_stream-1">on_request_end_stream/1</a></td><td></td></tr><tr><td valign="top"><a href="#on_send_push_promise-2">on_send_push_promise/2</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="init-2"></a>

### init/2 ###

<pre><code>
init(ConnPid, StreamId) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>ConnPid = pid()</code></li><li><code>StreamId = <a href="#type-stream_id">stream_id()</a></code></li><li><code>Result = {ok, <a href="#type-state">state()</a>}</code></li></ul>

<a name="on_receive_request_data-2"></a>

### on_receive_request_data/2 ###

`on_receive_request_data(Bin, ?S) -> any()`

<a name="on_receive_request_headers-2"></a>

### on_receive_request_headers/2 ###

<pre><code>
on_receive_request_headers(Headers, State) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Headers = <a href="#type-h2_headers">h2_headers()</a></code></li><li><code>State = <a href="#type-state">state()</a></code></li><li><code>Result = {ok, <a href="#type-state">state()</a>}</code></li></ul>

<a name="on_request_end_stream-1"></a>

### on_request_end_stream/1 ###

`on_request_end_stream(?S) -> any()`

<a name="on_send_push_promise-2"></a>

### on_send_push_promise/2 ###

`on_send_push_promise(Headers, ?S) -> any()`


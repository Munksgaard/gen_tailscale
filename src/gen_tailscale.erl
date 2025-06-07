%%
%% %CopyrightBegin%
%%
%% SPDX-License-Identifier: Apache-2.0
%%
%% Copyright Ericsson AB 1997-2025. All Rights Reserved.
%% Copyright Philip Munksgaard 2025. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

-module(gen_tailscale).
-moduledoc """
Interface to TCP/IP sockets over a [Tailscale](https://tailscale.com/) network.

This module provides
[`gen_tcp`](https://www.erlang.org/doc/apps/kernel/gen_tcp.html)-like
functionality for accepting connections over a
[Tailscale](https://tailscale.com/) network using
[libtailscale](https://github.com/tailscale/libtailscale/).

> #### Warning {: .warning}
>
> This is a rough proof-of-concept. It uses crudely modified versions of the
> original `gen_tcp` and
> [`gen_tcp_socket`](https://github.com/erlang/otp/blob/master/lib/kernel/src/gen_tcp_socket.erl)
> modules to manage the tcp-sockets and should probably not be used for anything
> important as is.
>
> Most of the documentation in here is left-over from `gen_tcp` and cannot be
> counted on to work as advertised.
""".


-compile(nowarn_deprecated_catch).

-export([connect/2, connect/3, connect/4,
         listen/2,
         accept/1, accept/2,
	 shutdown/2, close/1]).
-export([send/2, recv/2, recv/3, unrecv/2]).
-export([controlling_process/2]).
-export([fdopen/2]).

-include("inet_int.hrl").
-include("file.hrl").

-define(module_socket(Handler, Handle),
        {'$inet', (Handler), (Handle)}).

-type option() ::
        {active,          true | false | once | -32768..32767} |
        {buffer,          non_neg_integer()} |
        {debug,           boolean()} |
        {delay_send,      boolean()} |
        {deliver,         port | term} |
        {dontroute,       boolean()} |
        {exit_on_close,   boolean()} |
        {exclusiveaddruse, boolean()} |
        {header,          non_neg_integer()} |
        {high_msgq_watermark, pos_integer()} |
        {high_watermark,  non_neg_integer()} |
        {keepalive,       boolean()} |
        {linger,          {boolean(), non_neg_integer()}} |
        {low_msgq_watermark, pos_integer()} |
        {low_watermark,   non_neg_integer()} |
        {mode,            list | binary} | list | binary |
        {nodelay,         boolean()} |
        {packet,
         0 | 1 | 2 | 4 | raw | sunrm |  asn1 |
         cdr | fcgi | line | tpkt | http | httph | http_bin | httph_bin } |
        {packet_size,     non_neg_integer()} |
        {priority,        non_neg_integer()} |
        {raw,
         Protocol :: non_neg_integer(),
         OptionNum :: non_neg_integer(),
         ValueBin :: binary()} |
        {recbuf,          non_neg_integer()} |
        {reuseaddr,       boolean()} |
        {reuseport,       boolean()} |
        {reuseport_lb,    boolean()} |
        {send_timeout,    timeout()} |
        {send_timeout_close, boolean()} |
        {show_econnreset, boolean()} |
        {sndbuf,          non_neg_integer()} |
        {tos,             non_neg_integer()} |
        {tclass,          non_neg_integer()} |
        {ttl,             non_neg_integer()} |
	{recvtos,         boolean()} |
	{recvtclass,      boolean()} |
	{recvttl,         boolean()} |
	{ipv6_v6only,     boolean()}.

-doc """
Value from socket option [`pktoptions`](`t:option_name/0`).

If the platform implements the IPv4 option `IP_PKTOPTIONS`,
or the IPv6 option `IPV6_PKTOPTIONS` or `IPV6_2292PKTOPTIONS` for the socket;
this value is returned from `inet:getopts/2` when called with the option name
[`pktoptions`](`t:option_name/0`).

> #### Note {: .info }
>
> This option appears to be VERY Linux specific, and its existence in future
> Linux kernel versions is also worrying since the option is part of RFC 2292
> which is since long (2003) obsoleted by RFC 3542 that _explicitly_ removes
> this possibility to get packet information from a stream socket. For
> comparison: it has existed in FreeBSD but is now removed, at least since
> FreeBSD 10.
""".
-type pktoptions_value() ::
        {pktoptions, inet:ancillary_data()}.

-type option_name() ::
        active |
        buffer |
        debug |
        delay_send |
        deliver |
        dontroute |
        exit_on_close |
        exclusiveaddruse |
        header |
        high_msgq_watermark |
        high_watermark |
        keepalive |
        linger |
        low_msgq_watermark |
        low_watermark |
        mode |
        nodelay |
        packet |
        packet_size |
        priority |
        {raw,
         Protocol :: non_neg_integer(),
         OptionNum :: non_neg_integer(),
         ValueSpec :: (ValueSize :: non_neg_integer()) |
                      (ValueBin :: binary())} |
        recbuf |
        reuseaddr |
        reuseport |
        reuseport_lb |
        send_timeout |
        send_timeout_close |
        show_econnreset |
        sndbuf |
        tos |
        tclass |
        ttl |
        recvtos |
        recvtclass |
        recvttl |
        pktoptions |
	ipv6_v6only.
-type connect_option() ::
        {fd, Fd :: non_neg_integer()} |
        inet:address_family() |
        {ifaddr, socket:sockaddr_in() | socket:sockaddr_in6() |
                 inet:socket_address()} |
        {ip, inet:socket_address()} |
        {port, inet:port_number()} |
        {tcp_module, module()} |
        {netns, file:filename_all()} |
        {bind_to_device, binary()} |
        option().
-type listen_option() ::
        {fd, Fd :: non_neg_integer()} |
        inet:address_family() |
        {ifaddr, socket:sockaddr_in() | socket:sockaddr_in6() |
                 inet:socket_address()} |
        {ip, inet:socket_address()} |
        {port, inet:port_number()} |
        {backlog, B :: non_neg_integer()} |
        {tcp_module, module()} |
        {netns, file:filename_all()} |
        {bind_to_device, binary()} |
        option().
-doc """
As returned by [`accept/1,2`](`accept/1`) and [`connect/3,4`](`connect/3`).
""".
-type socket() :: inet:socket().

-export_type([option/0, option_name/0, connect_option/0, listen_option/0,
              socket/0, pktoptions_value/0]).


%% -define(DBG(T), erlang:display({{self(), ?MODULE, ?LINE, ?FUNCTION_NAME}, T})).


%%
%% Connect a socket
%%

-doc "Equivalent to [`connect(SockAddr, Opts, infinity)`](`connect/3`).".
-doc(#{since => <<"OTP 24.3">>}).
-spec connect(SockAddr, Opts) -> {ok, Socket} | {error, Reason} when
      SockAddr :: socket:sockaddr_in() | socket:sockaddr_in6(),
      Opts     :: [inet:inet_backend() | connect_option()],
      Socket   :: socket(),
      Reason   :: inet:posix().

connect(SockAddr, Opts) ->
    connect(SockAddr, Opts, infinity).

-doc """
Create a socket connected to the specified address.

### With arguments `Address` and `Port`

Equivalent to [`connect(Address, Port, Opts, infinity)`](`connect/4`).

### With argument `SockAddr` **(since OTP 24.3)**

Connects to a remote listen socket specified by `SockAddr`
where `t:socket:sockaddr_in6/0` for example allows specifying
the `scope_id` for link local IPv6 addresses.

[IPv4 addresses](`t:socket:sockaddr_in/0`) on the same
`t:map/0` format is also allowed.

Equivalent to `connect/4`, besides the format of the destination address.
""".
-spec connect(Address, Port, Opts) -> {ok, Socket} | {error, Reason} when
      Address  :: inet:socket_address() | inet:hostname(),
      Port     :: inet:port_number(),
      Opts     :: [inet:inet_backend() | connect_option()],
      Socket   :: socket(),
      Reason   :: inet:posix();
             (SockAddr, Opts, Timeout) -> {ok, Socket} | {error, Reason} when
      SockAddr :: socket:sockaddr_in() | socket:sockaddr_in6(),
      Opts     :: [inet:inet_backend() | connect_option()],
      Timeout  :: timeout(),
      Socket   :: socket(),
      Reason   :: timeout | inet:posix().

connect(Address, Port, Opts)
  when is_tuple(Address) orelse
       is_list(Address)  orelse
       is_atom(Address)  orelse
       (Address =:= any) orelse
       (Address =:= loopback) ->
    connect(Address, Port, Opts, infinity);
connect(#{family := Fam} = SockAddr, Opts, Timeout)
  when ((Fam =:= inet) orelse (Fam =:= inet6)) ->
    %% Ensure that its a proper sockaddr_in6, with all fields
    %% ?DBG([{fam, Fam}, {sa, SockAddr}, {opts, Opts}, {timeout, Timeout}]),
    SockAddr2 = inet:ensure_sockaddr(SockAddr),
    %% ?DBG([{sa2, SockAddr2}]),
    gen_tailscale_socket:connect(SockAddr2, Opts, Timeout).


-doc """
Create a socket connected to the specified address.

Creates a socket and connects it to a server on TCP port `Port`
on the host with IP address `Address`, that may also be a hostname.

### `Opts` (connect options)

- **`{ip, Address}`** - If the local host has many IP addresses,
  this option specifies which one to use.

- **`{ifaddr, Address}`** - Same as `{ip, Address}`.

  However, if `Address` instead is a `t:socket:sockaddr_in/0` or
  `t:socket:sockaddr_in6/0` this takes precedence over any value
  previously set with the `ip` and `port` options. If these options
  (`ip` or/and `port`) however comes _after_ this option,
  they may be used to _update_ the corresponding fields of this option
  (for `ip`, the `addr` field, and for `port`, the `port` field).

- **`{fd, integer() >= 0}`** - If a socket has somehow been connected without
  using `gen_tailscale`, use this option to pass the file descriptor for it.
  If `{ip, Address}` and/or `{port, port_number()}` is combined
  with this option, the `fd` is bound to the specified interface
  and port before connecting. If these options are not specified,
  it is assumed that the `fd` is already bound appropriately.

- **`inet`** - Sets up the socket for IPv4.

- **`inet6`** - Sets up the socket for IPv6.

- **`local`** - Sets up a Unix Domain Socket. See `t:inet:local_address/0`

- **`{port, Port}`** - Specifies which local port number to use.

- **`{tcp_module, module()}`** - Overrides which callback module is used.
  Defaults to `inet_tcp` for IPv4 and `inet6_tcp` for IPv6.

- **`t:option/0`** - See `inet:setopts/2`.

### Socket Data

Packets can be sent to the peer (outbound) with
[`send(Socket, Packet)`](`send/2`).  Packets sent from the peer
(inbound) are delivered as messages to the socket owner;
the process that created the socket, unless `{active, false}`
is specified in the `Options` list.

#### Active mode socket messages

- **`{tcp, Socket, Data}`** - Inbound data from the socket.

- **`{tcp_passive, Socket}`** -
  The socket was in `{active, N}` mode (see `inet:setopts/2` for details)
  and its message counter reached `0`, indicating that
  the socket has transitioned to passive (`{active, false}`) mode.


- **`{tcp_closed, Socket}`** - The socket was closed.

- **`{tcp_error, Socket, Reason}`** A socket error occurred.

#### Passive mode

If `{active, false}` is specified in the option list for the socket,
packets and errors are retrieved by calling [`recv/2,3`](`recv/3`)
(`send/2` may also return errors).

#### Timeout

The optional `Timeout` parameter specifies a connect time-out in milliseconds.
Defaults to `infinity`.

> #### Note {: .info }
>
> Keep in mind that if the underlying OS `connect()` call returns a timeout,
> `gen_tailscale:connect` will also return a timeout (i.e. `{error, etimedout}`),
> even if a larger `Timeout` was specified (for example `infinity`).

> #### Note {: .info }
>
> The default values for options specified to `connect` can be affected by the
> Kernel configuration parameter `inet_default_connect_options`.
> For details, see `m:inet`.
""".
-spec connect(Address, Port, Opts, Timeout) ->
                     {ok, Socket} | {error, Reason} when
      Address :: inet:socket_address() | inet:hostname(),
      Port    :: inet:port_number(),
      Opts    :: [inet:inet_backend() | connect_option()],
      Timeout :: timeout(),
      Socket  :: socket(),
      Reason  :: timeout | inet:posix().

connect(Address, Port, Opts0, Timeout) ->
    gen_tailscale_socket:connect(Address, Port, Opts0, Timeout).

%%
%% Listen on a tcp port
%%

-doc """
Create a listen socket.

Creates a socket and sets it to listen on port `Port` on the local host.

If `Port == 0`, the underlying OS assigns an available (ephemeral)
port number, use `inet:port/1` to retrieve it.

The following options are available:

- **`list`** - Received `Packet`s are delivered as lists of bytes,
  `[`[`byte/0`](`t:byte/0`)`]`.

- **`binary`** - Received `Packet`s are delivered as `t:binary/0`s.

- **`{backlog, B}`** - `B ::` `t:non_neg_integer/0`. The backlog value
  defines the maximum length that the queue of pending connections
  can grow to. Defaults to `5`.

- **`inet6`** - Sets up the socket for IPv6.

- **`inet`** - Sets up the socket for IPv4.

- **`{fd, Fd}`** - If a socket has somehow been created without using
  `gen_tailscale`, use this option to pass the file descriptor for it.

- **`{ip, Address}`** - If the host has many IP addresses, this option
  specifies which one to listen on.

- **`{port, Port}`** - Specifies which local port number to use.

- **`{ifaddr, Address}`** - Same as `{ip, Address}`.

  However, if this instead is an `t:socket:sockaddr_in/0` or
  `t:socket:sockaddr_in6/0` this takes precedence over any value
  previously set with the `ip` and `port` options. If these options
  (`ip` or/and `port`) however comes _after_ this option,
  they may be used to _update_ their corresponding fields of this option
  (for `ip`, the `addr` field, and for `port`, the `port` field).

- **`{tcp_module, module()}`** - Overrides which callback module is used.
  Defaults to `inet_tcp` for IPv4 and `inet6_tcp` for IPv6.

- **`t:option/0`** - See `inet:setopts/2`.

The returned socket `ListenSocket` should be used when calling
[`accept/1,2`](`accept/1`) to accept an incoming connection request.

> #### Note {: .info }
>
> The default values for options specified to `listen` can be affected by the
> Kernel configuration parameter `inet_default_listen_options`. For details, see
> `m:inet`.
""".
-spec listen(Port, Options) -> {ok, ListenSocket} | {error, Reason} when
      Port :: inet:port_number(),
      Options :: [inet:inet_backend() | listen_option()],
      ListenSocket :: socket(),
      Reason :: system_limit | inet:posix().

listen(Port, Opts0) ->
    %% ?DBG([{port, Port}, {opts0, Opts0}]),
    gen_tailscale_socket:listen(Port, Opts0).

    %% case inet:gen_tcp_module(Opts0) of
    %%     {?MODULE, Opts1} ->
    %%         %% ?DBG([{opts1, Opts1}]),
    %%         {Mod, Opts} = inet:tcp_module(Opts1),
    %%         %% ?DBG([{mod, Mod}, {opts, Opts}]),
    %%         case Mod:getserv(Port) of
    %%             {ok, TP} ->
    %%                 %% ?DBG([{tp, TP}]),
    %%                 Mod:listen(TP, Opts);
    %%             {error,einval} ->
    %%                 %% ?DBG("failed getserv (einval)"),
    %%                 exit(badarg);
    %%             Other -> Other
    %%         end;
    %%     {GenTcpMod, Opts} ->
    %%         GenTcpMod:listen(Port, Opts)
    %% end.

%%
%% Generic tcp accept
%%

-doc(#{equiv => accept(ListenSocket, infinity)}).
-spec accept(ListenSocket) -> {ok, Socket} | {error, Reason} when
      ListenSocket :: socket(),
      Socket :: socket(),
      Reason :: closed | system_limit | inet:posix().

accept(?module_socket(GenTcpMod, _) = S) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, infinity);
accept(S) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:accept(S);
	Error ->
	    Error
    end.

-doc """
Accept an incoming connection request on a listen socket.

`Socket` must be a socket returned from `listen/2`. `Timeout` specifies
a time-out value in milliseconds. Defaults to `infinity`.

Returns:

- `{ok, Socket}` if a connection is established
- `{error, closed}` if `ListenSocket` is closed
- `{error, timeout}` if no connection is established within `Timeout`
- `{error, system_limit}` if all available ports in the Erlang emulator
  are in  use
- A POSIX error value if something else goes wrong, see `m:inet`
  about possible values

To send packets (outbound) on the returned `Socket`, use `send/2`.
Packets sent from the peer (inbound) are delivered as messages
to the socket owner; the process that created the socket.
Unless `{active, false}` is specified in the option list when creating
the [listening socket](`listen/2`).

See `connect/4` about _active mode_ socket messages and _passive mode_.

> #### Note {: .info }
>
> The `accept` call _doesn't have to be_ issued from the socket owner process.
> Using version 5.5.3 and higher of the emulator, multiple simultaneous accept
> calls can be issued from different processes, which allows for a pool of
> acceptor processes handling incoming connections.
""".
-spec accept(ListenSocket, Timeout) -> {ok, Socket} | {error, Reason} when
      ListenSocket :: socket(),
      Timeout :: timeout(),
      Socket :: socket(),
      Reason :: closed | timeout | system_limit | inet:posix().

accept(?module_socket(GenTcpMod, _) = S, Time) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, Time);
accept(S, Time) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:accept(S, Time);
	Error ->
	    Error
    end.

%%
%% Generic tcp shutdown
%%

-doc """
Close the socket in one or both directions.

`How == write` means closing the socket for writing, reading from it is still
possible.

If `How == read` or there is no outgoing data buffered in the `Socket` port, the
shutdown is performed immediately and any error encountered is returned in
`Reason`.

If there is data buffered in the socket port, shutdown isn't performed
on the socket until that buffered data has been written to the OS
protocol stack.  If any errors are encountered, the socket is closed
and `{error, closed}` is returned by the next `recv/2` or `send/2` call.

Option `{exit_on_close, false}` is useful if the peer performs a shutdown
of its write side.  Then the socket stays open for writing after
receive has indicated that the socket was closed.

[](){: #async_shutdown_write }

> #### Note {: .info }
>
> Async shutdown write (`How :: write | read_write`).
>
> If the shutdown attempt is made while the inet driver is sending
> buffered data in the background, the shutdown is postponed until
> all buffered data has been sent.  This function immediately returns `ok`,
> and the caller _isn't_ informed (that the shutdown has been postponed).
>
> When using `inet_backend = socket`, the behaviour is different. A shutdown
> with `How :: write | read_write` will always be performed _immediately_.
""".
-spec shutdown(Socket, How) -> ok | {error, Reason} when
      Socket :: socket(),
      How :: read | write | read_write,
      Reason :: inet:posix().

shutdown(?module_socket(GenTcpMod, _) = S, How) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, How);
shutdown(S, How) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:shutdown(S, How);
	Error ->
	    Error
    end.

%%
%% Close
%%

-doc """
Close a TCP socket.

Note that in most implementations of TCP, doing a `close` does not guarantee
that the data sent is delivered to the recipient.  It is guaranteed that
the recepient will see all sent data before getting the close, but the
sender gets no indication of that.

If the sender needs to know that the recepient has received all data
there are two common ways to achieve this:

1. Use [`gen_tailscale:shutdown(Sock, write)`](`shutdown/2`) to signal that no more
   data is to be sent and wait for the other side to acknowledge seeing
   its read side being closed, by closing its write side, which shows
   as a socket close on this side.
2. Implement an acknowledgement in the protocol on top of TCP
   that both connection ends adhere to, indicating that all data
   has been seen.  The socket option [`{packet, N}`](`m:inet#option-packet`)
   may be useful.
""".
-spec close(Socket) -> ok when
      Socket :: socket().

close(?module_socket(GenTcpMod, _) = S) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S);
close(S) ->
    inet:tcp_close(S).

%%
%% Send
%%

-doc """
Send a packet on a socket.

There is no `send/2` call with a time-out option; use socket option
`send_timeout` if time-outs are desired.  See section
[Examples](#module-examples).

The return value `{error, {timeout, RestData}}` can only be returned when
`inet_backend = socket`.

[](){: #non_blocking_send }

> #### Note {: .info }
>
> #### Non-blocking send.
>
> If the user tries to send more data than there is room for in the OS send
> buffers, the 'rest data' is stored in (inet driver) internal buffers and later
> sent in the background. The function immediately returns ok (_not_ informing
> the caller that some date isn'nt sent yet). Any issue while
> sending the 'rest data' may be returned later.
>
> When using `inet_backend = socket`, the behaviour is different. There is
> _no_ buffering, instead the caller will "hang" until all of the data
> has been sent or the send timeout (as specified by the `send_timeout`
> option) expires (the function can "hang" even when using the `inet`
> backend if the internal buffers are full).
>
> If this happens when using `packet =/= raw`, a partial packet has been
> written. A new packet therefore _mustn't_ be written at this point,
> as there is no way for the peer to distinguish this from data in
> the current packet. Instead, set the `packet` option to `raw`, send the
> rest data (as raw data) and then set `packet` back to the correct type.
""".
-spec send(Socket, Packet) -> ok | {error, Reason} when
      Socket   :: socket(),
      Packet   :: iodata(),
      Reason   :: closed | {timeout, RestData} | inet:posix(),
      RestData :: binary() | erlang:iovec().

send(?module_socket(GenTcpMod, _) = S, Packet) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, Packet);
send(S, Packet) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:send(S, Packet);
	Error ->
	    Error
    end.

%%
%% Receive data from a socket (passive mode)
%%

-doc(#{equiv => recv(Socket, Length, infinity)}).
-spec recv(Socket, Length) -> {ok, Packet} | {error, Reason} when
      Socket :: socket(),
      Length :: non_neg_integer(),
      Packet :: string() | binary() | HttpPacket,
      Reason :: closed | inet:posix(),
      HttpPacket :: term().

recv(?module_socket(GenTcpMod, _) = S, Length) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, Length, infinity).

-doc """
Receive a packet, from a socket in _passive mode_.

A closed socket is indicated by the return value `{error, closed}`.
If the socket is not in passive mode, the return value is `{error, einval}`.

Argument `Length` is only meaningful when the socket is in `raw` mode and
denotes the number of bytes to read.  If `Length` is `0`, all available
bytes are returned. If `Length > 0`, exactly `Length` bytes are returned,
or an error; except if the socket is closed from the other side,
then the last read before the one returning `{error, closed}`
may return less than `Length` bytes of data.

The optional `Timeout` parameter specifies a time-out in milliseconds.
Defaults to `infinity`.

Any process can receive data from a passive socket, even if that process is not
the controlling process of the socket. However, only one process can call this
function on a socket at any given time. Using simultaneous calls to `recv` is
not recommended as the behavior depends on the socket implementation,
and could return errors such as `{error, ealready}`.
""".
-spec recv(Socket, Length, Timeout) -> {ok, Packet} | {error, Reason} when
      Socket :: socket(),
      Length :: non_neg_integer(),
      Timeout :: timeout(),
      Packet :: string() | binary() | HttpPacket,
      Reason :: closed | timeout | inet:posix(),
      HttpPacket :: term().

recv(?module_socket(GenTcpMod, _) = S, Length, Time) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, Length, Time);
recv(S, Length, Time) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:recv(S, Length, Time);
	Error ->
	    Error
    end.

-doc false.
unrecv(?module_socket(GenTcpMod, _) = S, Data) when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, Data);
unrecv(S, Data) when is_port(S) ->
    case inet_db:lookup_socket(S) of
	{ok, Mod} ->
	    Mod:unrecv(S, Data);
	Error ->
	    Error
    end.

%%
%% Set controlling process
%%

-doc """
Change the controlling process (owner) of a socket.

Assigns a new controlling process `Pid` to `Socket`. The controlling process
is the process that the socket sends messages to.  If this function
is called from any other process than the current controlling process,
`{error, not_owner}` is returned.

If the process identified by `Pid` is not an existing local `t:pid/0`,
`{error, badarg}` is returned. `{error, badarg}` may also be returned
in some cases when `Socket` is closed during the execution of this function.

If the socket is in _active mode_, this function will transfer any messages
from the socket in the mailbox of the caller to the new controlling process.

If any other process is interacting with the socket during the transfer,
it may not work correctly and messages may remain in the caller's mailbox.
For instance, changing the sockets active mode during the transfer
could cause this.
""".
-spec controlling_process(Socket, Pid) -> ok | {error, Reason} when
      Socket :: socket(),
      Pid :: pid(),
      Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(?module_socket(GenTcpMod, _) = S, NewOwner)
  when is_atom(GenTcpMod) ->
    GenTcpMod:?FUNCTION_NAME(S, NewOwner);
controlling_process(S, NewOwner) ->
    case inet_db:lookup_socket(S) of
	{ok, _Mod} -> % Just check that this is an open socket
	    inet:tcp_controlling_process(S, NewOwner);
	Error ->
	    Error
    end.



%%
%% Create a port/socket from a file descriptor
%%
-doc false.
fdopen(Fd, Opts0) ->
    gen_tailscale_socket:fdopen(Fd, Opts0).

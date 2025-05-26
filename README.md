# gen_tailscale

This module provides
[`gen_tcp`](https://www.erlang.org/doc/apps/kernel/gen_tcp.html)-like
functionality for accepting connections over a
[Tailscale](https://tailscale.com/) network using
[libtailscale](https://github.com/tailscale/libtailscale/).

This module is based in the [`libtailscale` NIF
wrapper](https://hex.pm/packages/libtailscale) and is published at on Hex as
[`gen_tailscale`](https://hex.pm/packages/gen_tailscale). I've also released
[`tailscale_transport`](https://hex.pm/packages/tailscale_transport), which
allows users to expose their bandit/phoenix-based app directly to their tailnet
using `libtailscale` and `gen_tailscale` wrapper.

Everything in this chain of packages should be considered proof of concept at
this point and should not be used for anything important. Especially
`gen_tailscale`, which has been constructed by crudely hacking the original
`gen_tcp` module to use `libtailscale` and could use a total rewrite at some
point. However, it works well enough that my example application
[`tschat`](https://github.com/Munksgaard/tschat) is able to accept connections
from different Tailscale users and show their username by retrieving data from
the Tailscale connection.

> #### Warning {: .warning}
>
> This is a rough proof-of-concept. It uses crudely modified versions of the
> original `gen_tcp` and
> [`gen_tcp_socket`](https://github.com/erlang/otp/blob/master/lib/kernel/src/gen_tcp_socket.erl)
> modules to manage the tcp-sockets and should probably not be used for anything
> important as is.

## Examples

Start a simple echo server by running `mix run examples/echo.exs` or the following code:

```elixir
{:ok, lsock} =
  :gen_tailscale.listen(2000, active: false, hostname: "gen-tailscale-test", ephemeral: true)

{:ok, sock} = :gen_tailscale.accept(lsock)

IO.puts("Accepted connection from: #{inspect(:gen_tailscale_socket.getremoteaddr(sock))}")

{:ok, s} = :gen_tailscale.recv(sock, 0)
:ok = :gen_tailscale.send(sock, s)
:ok = :gen_tailscale.shutdown(sock, :read_write)
:ok = :gen_tailscale.close(sock)
:ok = :gen_tailscale.close(lsock)
```

It will ask you to log in by following a link.

Once logged in, connect from another terminal by running `telnet
gen-tailscale-test 2000`. You can now send a single message and have it echoed
back to you before the server closes.

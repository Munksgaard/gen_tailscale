{:ok, lsock} =
  :gen_tailscale.listen(2000, active: false, hostname: "gen-tailscale-test", ephemeral: true)

{:ok, sock} = :gen_tailscale.accept(lsock)

IO.puts("Accepted connection from: #{inspect(:gen_tailscale_socket.getremoteaddr(sock))}")

{:ok, s} = :gen_tailscale.recv(sock, 0)
:ok = :gen_tailscale.send(sock, s)
:ok = :gen_tailscale.shutdown(sock, :read_write)
:ok = :gen_tailscale.close(sock)
:ok = :gen_tailscale.close(lsock)

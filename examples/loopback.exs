# Example of using gen_tailscale loopback server
#
# This example demonstrates how to start a Tailscale loopback server
# that provides both SOCKS5 proxy and LocalAPI access using an existing socket.

# First, create a listen socket (which establishes the Tailscale connection)
{:ok, listen_socket} =
  :gen_tailscale.listen(0, [
    {:hostname, "gen-tailscale-loopback-test"},
    {:ephemeral, true},
    {:active, false}
  ])

# Start the loopback server using the existing socket's Tailscale connection
case :gen_tailscale.start_loopback(listen_socket) do
  {:ok, {address, proxy_cred, local_api_cred}} ->
    IO.puts("✓ Loopback server started successfully!")
    IO.puts("Address: #{address}")
    IO.puts("Proxy credential: #{proxy_cred}")
    IO.puts("LocalAPI credential: #{local_api_cred}")

    # Parse the address (convert charlist to string if needed)
    address_str = if is_list(address), do: to_string(address), else: address
    [host, port] = String.split(address_str, ":")
    port = String.to_integer(port)

    IO.puts("\n--- Usage Instructions ---")
    IO.puts("SOCKS5 Proxy:")
    IO.puts("  Server: #{host}:#{port}")
    IO.puts("  Username: tsnet")
    IO.puts("  Password: #{proxy_cred}")

    IO.puts("\nLocalAPI Access:")
    IO.puts("  Base URL: http://#{address_str}/localapi")
    IO.puts("  Headers:")
    IO.puts("    Sec-Tailscale: localapi")
    IO.puts("    Authorization: Basic #{Base.encode64(":#{local_api_cred}")}")

    # Example LocalAPI usage (manual testing)
    IO.puts("\n--- Testing LocalAPI ---")
    IO.puts("To test the LocalAPI manually, use curl:")
    auth = Base.encode64(":#{local_api_cred}")

    IO.puts(
      "curl -H 'Sec-Tailscale: localapi' -H 'Authorization: Basic #{auth}' -H 'Host: #{address_str}' http://#{host}:#{port}/localapi/v0/status"
    )

    IO.puts("\nNote: The loopback server is now running and ready to accept connections.")

    Process.sleep(10_000)

    # Clean up the listen socket when done
    :gen_tailscale.close(listen_socket)

  {:error, reason} ->
    IO.puts("✗ Failed to start loopback server: #{inspect(reason)}")
    :gen_tailscale.close(listen_socket)
end

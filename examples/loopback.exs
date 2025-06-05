# Example of using gen_tailscale loopback server
#
# This example demonstrates how to start a Tailscale loopback server
# that provides both SOCKS5 proxy and LocalAPI access.

# Start the loopback server with options
case :gen_tailscale.start_loopback([
  {:hostname, "gen-tailscale-loopback-test"},
  {:ephemeral, true}
]) do
  {:ok, {address, proxy_cred, local_api_cred}} ->
    IO.puts("✓ Loopback server started successfully!")
    IO.puts("Address: #{address}")
    IO.puts("Proxy credential: #{proxy_cred}")
    IO.puts("LocalAPI credential: #{local_api_cred}")
    
    # Parse the address
    [host, port] = String.split(address, ":")
    port = String.to_integer(port)
    
    IO.puts("\n--- Usage Instructions ---")
    IO.puts("SOCKS5 Proxy:")
    IO.puts("  Server: #{host}:#{port}")
    IO.puts("  Username: tsnet")
    IO.puts("  Password: #{proxy_cred}")
    
    IO.puts("\nLocalAPI Access:")
    IO.puts("  Base URL: http://#{address}/localapi")
    IO.puts("  Headers:")
    IO.puts("    Sec-Tailscale: localapi")
    IO.puts("    Authorization: Basic #{Base.encode64(":#{local_api_cred}")}")
    
    # Example LocalAPI request to get status
    IO.puts("\n--- Testing LocalAPI ---")
    auth = Base.encode64(":#{local_api_cred}")
    headers = [
      {'Authorization', String.to_charlist("Basic #{auth}")},
      {'Host', String.to_charlist(address)},
      {'Sec-Tailscale', 'localapi'}
    ]
    
    url = String.to_charlist("http://#{host}:#{port}/localapi/v0/status")
    
    case :httpc.request(:get, {url, headers}, [], []) do
      {:ok, {{_version, 200, _reason_phrase}, _response_headers, body}} ->
        IO.puts("✓ LocalAPI status request successful!")
        IO.puts("Response: #{body}")
      {:ok, {{_version, status_code, reason_phrase}, _response_headers, body}} ->
        IO.puts("✗ LocalAPI request failed with status #{status_code}: #{reason_phrase}")
        IO.puts("Response: #{body}")
      {:error, reason} ->
        IO.puts("✗ LocalAPI request failed: #{inspect(reason)}")
    end
    
  {:error, reason} ->
    IO.puts("✗ Failed to start loopback server: #{inspect(reason)}")
end
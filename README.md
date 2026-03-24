# vpn setup

Corporate VPN is awful, how to avoid using it except when absolutely necessary.

WireGuard available for transparent full-tunnel routing. See [WireGuard](#wireguard) below.

# auth

Make sure you have `auth.env`

    CLV_USERNAME=
    CLV_PASSWORD=
    CLV_SERVER=

Then just run `auth.sh` which results in `config.env` for the next stage

## avoiding all this bullshit

run openconnect directly for normal usage

    . ./config.env
    sudo openconnect --cookie=$OPENCONNECT_AUTH_COOKIE \
        --servercert=$OPENCONNECT_AUTH_SERVERCERT \
        --server $OPENCONNECT_AUTH_SERVER

Stop reading now

## but i want my life to be difficult

Ok you hate your VPN, I get it.

We're going to be running VPN in an isolated container, with a SOCKS/HTTP/DNS proxy

### prereqs

IMPORTANT: run this to allow namespace switching

    sudo setcap cap_sys_admin,cap_sys_ptrace,cap_net_admin+ep $(which nsenter)

### usage


Docker compose brings up the whole thing

    docker compose up

expected usage is either via entering a netns with `vpndo $CMD` or using the proxy `pp $CMD`

    # enter into vpn netns
    vpndo() {
        VPN_CONTEXT=1 command nsenter --target $(docker inspect --format "{{.State.Pid}}" vpn-vpn-1) --net --setuid $(id -u) "$@"
    }
    
    # vpn proxy
    alias -g pp="https_proxy=http://localhost:8118 http_proxy=http://localhost:8118"


### DNS via dnsmasq

Your vpn may create some resolv.conf entries to point to special vpn dns servers - but this is inside a container now
and we don't have access to it from our netns'd host

we run a dnsmasq on 127.0.0.53 to proxy the dns-defined DNS servers

we also test each one since my corporate vpns keep randomly breaking

### verify it even works

Now we can test namespace usage:

    vpndo whoami
    vpndo id

We now have a VPN in a network namespace, a http(s) proxy on localhost:8118, and a socks5 proxy on localhost:1080

We use it either with `vpndo` for shell commands, or http/socks proxies for applications

We can `vpndo zsh` to enter a shell in which everything will use the VPN.

Test it out

    $ curl ifconfig.co # no vpn
    159.xxx.xxx.xxx 

    $ vpndo curl ifconfig.co # vpn via network namespace
    8.xxx.xxx.xxx 
    
    $ pp curl ifconfig.co # vpn via http proxy
    8.xxx.xxx.xxx 

    $ curl --socks5 localhost:1080 ifconfig.co # vpn ip via socks
    8.xxx.xxx.xxx 

    $ pp python test.py # look it works for python too
    Checking external IP address...
    IP Address: 8.....
    Country: United States
    City: Unknown

    $ vpndo zsh # enter a shell in the vpn network namespace
    $ curl ifconfig.co # now everything is in the vpn
    8.......

Use a separate browser for vpn, or configure a specific firefox container.

## WireGuard

All traffic goes through the VPN tunnel. LAN traffic (192.168.0.x) is excluded automatically — `wg-quick` installs a `suppress_prefixlength` routing rule so any more-specific route in your main table wins over the tunnel.

### Registering a client

On the server, give the client a name:

```bash
./setup-wireguard-client.sh laptop
./setup-wireguard-client.sh phone
```

This generates a keypair, assigns the client an IP (`10.99.1.2`, `.3`, etc.), registers it with the WireGuard server, and saves a config to `wireguard/config/clients/<name>.conf`.

Copy it to the client:

```bash
scp wireguard/config/clients/laptop.conf user@laptop:/etc/wireguard/wg0.conf
```

Then on the client:

```bash
sudo wg-quick up wg0
```

Check the `Endpoint` in the generated config — the script tries to detect the server's LAN IP but you may need to correct it.

### Managing the tunnel

```bash
sudo wg-quick up wg0      # connect
sudo wg-quick down wg0    # disconnect
sudo wg show              # status
```

### Troubleshooting

```bash
# Check the wireguard container is up and happy
docker compose logs wireguard

# Verify the peer is registered
sudo wg show

# If the tunnel is up but corp DNS isn't resolving
resolvectl status wg0   # should show DNS: 10.99.1.1

# Nuclear option — regenerate everything
sudo wg-quick down wg0
rm wireguard/config/*.key
docker compose restart wireguard
./setup-wireguard-client.sh
```

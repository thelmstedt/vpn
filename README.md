# vpn setup

Corporate VPN is awful, how to avoid using it except when absolutely necessary.

We're going to be running VPN in an isolated container, with a SOCKS/HTTP/DNS proxy

Docker compose brings up the whole thing

    docker compose up

We now have:

* vpn in an isolated container
* a keepalive heartbeat
* a dnsmasq republishing the discovered servers from vpn setup
* http(s) proxy (using dns) on localhost:8118
* a socks5 proxy (using dns) on localhost:1080
* wireguard for directly connecting without reauth

## auth

Authentication must be done separately. You're expected to have `config.env` with:

    OPENCONNECT_AUTH_COOKIE='xxx'
    OPENCONNECT_AUTH_SERVERCERT='xxx'
    OPENCONNECT_AUTH_SERVER='https://xxx.example.com'

Run `uv run ./auth/openconnect_auth.py` to auth in a local chrome which has been started with
`--remote-debugging-port=9222`

## usage

* chrome: needs to be started with `--proxy-server="socks5://$IP_ADDR:1080"`
* firefox: use container tabs, which can be configured individually to use vpn
* terminal: use netns (linux only) or `http_proxy/https_proxy` which is usually supported

A useful alias:

    # vpn proxy
    alias -g pp="https_proxy=http://localhost:8118 http_proxy=http://localhost:8118"

Test it out

    $ curl ifconfig.co # no vpn
    159.xxx.xxx.xxx 


    $ curl --socks5 localhost:1080 ifconfig.co # vpn ip via socks
    8.xxx.xxx.xxx 

### netns

If you're running this on linux you have network namespaces

IMPORTANT: run this to allow namespace switching (linux only)

    sudo setcap cap_sys_admin,cap_sys_ptrace,cap_net_admin+ep $(which nsenter)

We'll use this function in `.zshrc`:

    # enter into vpn netns
    vpndo() {
        VPN_CONTEXT=1 command nsenter --target $(docker inspect --format "{{.State.Pid}}" vpn-vpn-1) --net --setuid $(id -u) "$@"
    }

Test it out:

    $ vpndo zsh # enter a shell in the vpn network namespace
    $ vpndo curl ifconfig.co # or use it for a single command 

### WireGuard

Some services require a little more integration with VPN - e.g docker

Wireguard republishes the vpn so you can locally easily connect/disconnect without the auth dance

Intention was to extend this to other clients, but realistically it only works on the server, for reasons.

On the server, give the client a name:

    ./setup-wireguard-client.sh desktop

This generates a keypair, assigns the client an IP (`10.99.1.2`, `.3`, etc.), registers it with the WireGuard server,
and saves a config to `wireguard/config/clients/<name>.conf`.

Copy it in place

    scp wireguard/config/clients/laptop.conf /etc/wireguard/wg0.conf
    sudo wg-quick up wg0      # connect
    sudo wg-quick down wg0    # disconnect
    sudo wg show              # status


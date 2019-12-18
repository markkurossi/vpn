# vpn
Virtual Private Network for Everything

## DNS Server Configuration

### Query DNS Servers

    $ scutil --dns | grep nameserver

### Set DNS Servers

    $ networksetup -setdnsservers Wi-Fi 192.168.192.254
    $ networksetup -setdnsservers Wi-Fi 192.168.99.1

### Flush DNS Cache

This information is from [help.dreamhost.com](https://help.dreamhost.com/hc/en-us/articles/214981288-Flushing-your-DNS-cache-in-Mac-OS-X-and-Linux).

#### OSX 12 (Sierra) and later

    $ sudo killall -HUP mDNSResponder; sudo killall mDNSResponderHelper; sudo dscacheutil -flushcache

#### OS X 11 (El Capitan) and OS X 12 (Sierra)

    $ sudo killall -HUP mDNSResponder

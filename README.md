# SystemD Service files for PIA VPN Connections

This repository contains systemd service files to create native openvpn connections to the vpn provider known as pia.

## Requirements:

* `namespaced-openvpn`
* `curl`
* `jq`

## Installation:

Enter your credentials and the script path in the service file, link it to the correct location and enable it:
```
$ nano pia.service # enter your credentials
$ sudo ln -s netns@.service /etc/systemd/system/netns@.service
$ sudo ln -s pia.service /etc/systemd/system/pia.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable pia.service
```

## Usage:

Start the service:
```
$ sudo systemctl start pia.service
```

or without installation just run the script by yourself:

```
$ sudo PIA_USER="p1234567" PIA_PASS="abcdefghijkl" PIA_AUTOCONNECT="openvpn_udp_strong" PIA_DNS="true" PIA_PF="true" MAX_LATENCY=0.05 ./get_region_and_token.sh 2>/dev/null
```

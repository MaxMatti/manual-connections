#!/bin/bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This function allows you to check if the required tools have been installed.
function check_tool() {
  cmd=$1
  if ! command -v $cmd &>/dev/null
  then
    echo "$cmd could not be found"
    echo "Please install $cmd"
    exit 1
  fi
}
# Now we call the function to make sure we can use wg-quick, curl and jq.
check_tool curl
check_tool jq
check_tool namespaced-openvpn

if [[ ! $PIA_USER || ! $PIA_PASS ]]; then
  echo "Error: Please set your username and password!"
  exit 1
fi

PIA_AUTOCONNECT=${PIA_AUTOCONNECT:"openvpn_udp_strong"}
PIA_DNS=${PIA_DNS:true}
PIA_PF=${PIA_PF:true}
MAX_LATENCY=${MAX_LATENCY:-0.05}
export MAX_LATENCY

serverlist_url='https://serverlist.piaservers.net/vpninfo/servers/v4'

# This function checks the latency you have to a specific region.
# It will print a human-readable message to stderr,
# and it will print the variables to stdout
printServerLatency() {
  serverIP="$1"
  regionID="$2"
  regionName="$(echo ${@:3} |
    sed 's/ false//' | sed 's/true/(geo)/')"
  time=$(LC_NUMERIC=en_US.utf8 curl -o /dev/null -s \
    --connect-timeout $MAX_LATENCY \
    --write-out "%{time_connect}" \
    http://$serverIP:443)
  if [ $? -eq 0 ]; then
    echo $time $regionID $serverIP
  fi
}
export -f printServerLatency

echo -n "Getting the server list... "
# Get all region data since we will need this on multiple occasions
all_region_data=$(curl -s "$serverlist_url" | head -1)

# If the server list has less than 1000 characters, it means curl failed.
if [[ ${#all_region_data} -lt 1000 ]]; then
  echo "Could not get correct region data. To debug this, run:"
  echo "$ curl -v $serverlist_url"
  echo "If it works, you will get a huge JSON as a response."
  exit 1
fi

# Test one server from each region to get the closest region.
# If port forwarding is enabled, filter out regions that don't support it.
if [[ $PIA_PF == "true" ]]; then
  echo Port Forwarding is enabled, so regions that do not support
  echo port forwarding will get filtered out.
  summarized_region_data="$( echo $all_region_data |
    jq -r '.regions[] | select(.port_forward==true) |
    .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )"
else
  summarized_region_data="$( echo $all_region_data |
    jq -r '.regions[] |
    .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )"
fi
echo Testing regions that respond \
  faster than $MAX_LATENCY seconds:
bestRegion="$(echo "$summarized_region_data" |
  xargs -I{} bash -c 'printServerLatency {}' |
  sort | head -1 | awk '{ print $2 }')"

# Get all data for the best region
regionData="$( echo $all_region_data |
  jq --arg REGION_ID "$bestRegion" -r \
  '.regions[] | select(.id==$REGION_ID)')"

echo -n The closest region is "$(echo $regionData | jq -r '.name')"
if echo $regionData | jq -r '.geo' | grep true > /dev/null; then
  echo " (geolocated region)."
else
  echo "."
fi
echo
bestServer_meta_IP="$(echo $regionData | jq -r '.servers.meta[0].ip')"
bestServer_meta_hostname="$(echo $regionData | jq -r '.servers.meta[0].cn')"
bestServer_WG_IP="$(echo $regionData | jq -r '.servers.wg[0].ip')"
bestServer_WG_hostname="$(echo $regionData | jq -r '.servers.wg[0].cn')"
bestServer_OT_IP="$(echo $regionData | jq -r '.servers.ovpntcp[0].ip')"
bestServer_OT_hostname="$(echo $regionData | jq -r '.servers.ovpntcp[0].cn')"
bestServer_OU_IP="$(echo $regionData | jq -r '.servers.ovpnudp[0].ip')"
bestServer_OU_hostname="$(echo $regionData | jq -r '.servers.ovpnudp[0].cn')"

echo "Trying to get a new token by authenticating with the meta service..."
generateTokenResponse=$(curl -s -u "$PIA_USER:$PIA_PASS" \
  --connect-to "$bestServer_meta_hostname::$bestServer_meta_IP:" \
  --cacert "ca.rsa.4096.crt" \
  "https://$bestServer_meta_hostname/authv3/generateToken")
echo "$generateTokenResponse"

if [ "$(echo "$generateTokenResponse" | jq -r '.status')" != "OK" ]; then
  echo "Could not get a token. Please check your account credentials."
  echo
  echo "You can also try debugging by manually running the curl command:"
  echo $ curl -vs -u \"$PIA_USER:$PIA_PASS\" --cacert ca.rsa.4096.crt \
    --connect-to \"$bestServer_meta_hostname::$bestServer_meta_IP:\" \
    https://$bestServer_meta_hostname/authv3/generateToken
  exit 1
fi

token="$(echo "$generateTokenResponse" | jq -r '.token')"

# just making sure this variable doesn't contain some strange string
if [ "$PIA_PF" != true ]; then
  PIA_PF="false"
fi

serverIP=$bestServer_OU_IP
serverHostname=$bestServer_OU_hostname
if [[ $PIA_AUTOCONNECT == *tcp* ]]; then
  serverIP=$bestServer_OT_IP
  serverHostname=$bestServer_OT_hostname
fi

PIA_TOKEN="$token"
OVPN_SERVER_IP=$serverIP
OVPN_HOSTNAME=$serverHostname
CONNECTION_SETTINGS=$PIA_AUTOCONNECT

# Check if manual PIA OpenVPN connection is already initialized.
# Multi-hop is out of the scope of this repo, but you should be able to
# get multi-hop running with both OpenVPN and WireGuard.
adapter_check="$( ip a s tun06 2>&1 )"
should_read="Device \"tun06\" does not exist"
pid_filepath="/opt/piavpn-manual/pia_pid"
if [[ "$adapter_check" != *"$should_read"* ]]; then
  echo The tun06 adapter already exists, that interface is required
  echo for this configuration.
  if [ -f "$pid_filepath" ]; then
    old_pid="$( cat "$pid_filepath" )"
    old_pid_name="$( ps -p "$old_pid" -o comm= )"
    if [[ $old_pid_name == 'namespaced-openvpn' ]]; then
      echo
      echo It seems likely that process $old_pid is an OpenVPN connection
      echo that was established by using this script. Unless it is closed
      echo you would not be able to get a new connection.
      echo -n "Do you want to run $ kill $old_pid (Y/n): "
      read close_connection
    fi
    if echo ${close_connection:0:1} | grep -iq n ; then
      echo Closing script. Resolve tun06 adapter conflict and run the script again.
      exit 1
    fi
    echo Killing the existing OpenVPN process and waiting 5 seconds...
    kill $old_pid
    sleep 5
  fi
fi

# Create a credentials file with the login token
echo "Trying to write /opt/piavpn-manual/pia.ovpn...
"
mkdir -p /opt/piavpn-manual
rm -f /opt/piavpn-manual/credentials /opt/piavpn-manual/route_info
echo ${PIA_TOKEN:0:62}"
"${PIA_TOKEN:62} > /opt/piavpn-manual/credentials || exit 1
chmod 600 /opt/piavpn-manual/credentials

# Translate connection settings variable
IFS='_'
read -ra connection_settings <<< "$CONNECTION_SETTINGS"
IFS=' '
protocol="${connection_settings[1]}"
encryption="${connection_settings[2]}"

prefix_filepath="openvpn_config/standard.ovpn"
if [[ $encryption == "strong" ]]; then
  prefix_filepath="openvpn_config/strong.ovpn"
fi

if [[ $protocol == "udp" ]]; then
  if [[ $encryption == "standard" ]]; then
    port=1198
  else
    port=1197
  fi
else
  if [[ $encryption == "standard" ]]; then
    port=502
  else
    port=501
  fi
fi

# Create the OpenVPN config based on the settings specified
cat $prefix_filepath > /opt/piavpn-manual/pia.ovpn || exit 1
echo remote $OVPN_SERVER_IP $port $protocol >> /opt/piavpn-manual/pia.ovpn

# Copy the up/down scripts to /opt/piavpn-manual/
# based upon use of PIA DNS
if [ "$PIA_DNS" != true ]; then
  cp openvpn_config/openvpn_up.sh /opt/piavpn-manual/
  cp openvpn_config/openvpn_down.sh /opt/piavpn-manual/
else
  cp openvpn_config/openvpn_up_dnsoverwrite.sh /opt/piavpn-manual/openvpn_up.sh
  cp openvpn_config/openvpn_down_dnsoverwrite.sh /opt/piavpn-manual/openvpn_down.sh
fi

# Start the OpenVPN interface.
# If something failed, stop this script.
# If you get DNS errors because you miss some packages,
# just hardcode /etc/resolv.conf to "nameserver 10.0.0.242".
#rm -f /opt/piavpn-manual/debug_info
echo "
Trying to start the OpenVPN connection..."
namespaced-openvpn --daemon \
  --config "/opt/piavpn-manual/pia.ovpn" \
  --writepid "/opt/piavpn-manual/pia_pid" \
  --log "/opt/piavpn-manual/debug_info" || exit 1

echo "
The OpenVPN connect command was issued.

Confirming OpenVPN connection state... "

# Check if manual PIA OpenVPN connection is initialized.
# Manually adjust the connection_wait_time if needed
connection_wait_time=10
confirmation="Initialization Sequence Complete"
for (( timeout=0; timeout <=$connection_wait_time; timeout++ ))
do
  sleep 1
  if grep -q "$confirmation" /opt/piavpn-manual/debug_info; then
    connected=true
    break
  fi
done

ovpn_pid="$( cat /opt/piavpn-manual/pia_pid )"
gateway_ip="$( cat /opt/piavpn-manual/route_info )"

# Report and exit if connection was not initialized within 10 seconds.
if [ "$connected" != true ]; then
  echo "The VPN connection was not established within 10 seconds."
  kill $ovpn_pid
  exit 1
fi

echo "Initialization Sequence Complete!

At this point, internet should work via VPN.
"

echo "OpenVPN Process ID: $ovpn_pid
VPN route IP: $gateway_ip

To disconnect the VPN, run:

--> sudo kill $ovpn_pid <--
"

# This section will stop the script if PIA_PF is not set to "true".
if [ "$PIA_PF" != true ]; then
  exit
fi

echo "
This script got started with PIA_PF=true.
Starting procedure to enable port forwarding by running the following command:
$ PIA_TOKEN=\"$PIA_TOKEN\" \\
  PF_GATEWAY=\"$gateway_ip\" \\
  PF_HOSTNAME=\"$OVPN_HOSTNAME\" \\
  ./port_forwarding.sh
"

PIA_TOKEN=$PIA_TOKEN
PF_GATEWAY="$gateway_ip"
PF_HOSTNAME="$OVPN_HOSTNAME"

# The port forwarding system has required two variables:
# PAYLOAD: contains the token, the port and the expiration date
# SIGNATURE: certifies the payload originates from the PIA network.

# Basically PAYLOAD+SIGNATURE=PORT. You can use the same PORT on all servers.
# The system has been designed to be completely decentralized, so that your
# privacy is protected even if you want to host services on your systems.

# You can get your PAYLOAD+SIGNATURE with a simple curl request to any VPN
# gateway, no matter what protocol you are using. Considering WireGuard has
# already been automated in this repo, here is a command to help you get
# your gateway if you have an active OpenVPN connection:
# $ ip route | head -1 | grep tun | awk '{ print $3 }'
# This section will get updated as soon as we created the OpenVPN script.

# Get the payload and the signature from the PF API. This will grant you
# access to a random port, which you can activate on any server you connect to.
# If you already have a signature, and you would like to re-use that port,
# save the payload_and_signature received from your previous request
# in the env var PAYLOAD_AND_SIGNATURE, and that will be used instead.
if [[ ! $PAYLOAD_AND_SIGNATURE ]]; then
  echo "Getting new signature..."
  payload_and_signature="$(ip netns exec protected curl -s -m 5 \
    --connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    --cacert "ca.rsa.4096.crt" \
    -G --data-urlencode "token=${PIA_TOKEN}" \
    "https://${PF_HOSTNAME}:19999/getSignature")"
else
  payload_and_signature="$PAYLOAD_AND_SIGNATURE"
  echo "Using the following payload_and_signature from the env var:"
fi
echo "$payload_and_signature"
export payload_and_signature

# Check if the payload and the signature are OK.
# If they are not OK, just stop the script.
if [ "$(echo "$payload_and_signature" | jq -r '.status')" != "OK" ]; then
  echo "The payload_and_signature variable does not contain an OK status."
  exit 1
fi

# We need to get the signature out of the previous response.
# The signature will allow the us to bind the port on the server.
signature="$(echo "$payload_and_signature" | jq -r '.signature')"

# The payload has a base64 format. We need to extract it from the
# previous response and also get the following information out:
# - port: This is the port you got access to
# - expires_at: this is the date+time when the port expires
payload="$(echo "$payload_and_signature" | jq -r '.payload')"
port="$(echo "$payload" | base64 -d | jq -r '.port')"

# The port normally expires after 2 months. If you consider
# 2 months is not enough for your setup, please open a ticket.
expires_at="$(echo "$payload" | base64 -d | jq -r '.expires_at')"

# Display some information on the screen for the user.
echo "The signature is OK.

--> The port is $port and it will expire on $expires_at. <--

Trying to bind the port..."

PORT=$port ./after_port_forwarding.sh
systemd-notify --ready

# Now we have all required data to create a request to bind the port.
# We will repeat this request every 15 minutes, in order to keep the port
# alive. The servers have no mechanism to track your activity, so they
# will just delete the port forwarding if you don't send keepalives.
while true; do
  bind_port_response="$(ip netns exec protected curl -Gs -m 5 \
    --connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    --cacert "ca.rsa.4096.crt" \
    --data-urlencode "payload=${payload}" \
    --data-urlencode "signature=${signature}" \
    "https://${PF_HOSTNAME}:19999/bindPort")"
    echo "$bind_port_response"

    # If port did not bind, just exit the script.
    # This script will exit in 2 months, since the port will expire.
    export bind_port_response
    if [ "$(echo "$bind_port_response" | jq -r '.status')" != "OK" ]; then
      echo "The API did not return OK when trying to bind port. Exiting."
      exit 1
    fi
    echo Port $port refreshed on $(date). \
      This port will expire on $(date --date="$expires_at")

    # sleep 15 minutes
    sleep 900
done

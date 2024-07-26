#!/bin/bash

green='\033[0;32m'
red='\033[0;31m'
nc='\033[0m'

json=$(cat /etc/cloudcix/pod/configs/config.json)
pod_number=$(echo "$json" | jq -r '.pod_number')
enabled=$(echo "$json" | jq -r '.enabled')
ipv6_subnet=$(echo "$json" | jq -r '.ipv6_subnet')
IFS='/' read -ra ipv6 <<< "$ipv6_subnet"
ipv6_gateway="$ipv6"10:0:1/64

public_if="${red}DOWN${nc}"
private_if="${red}DOWN${nc}"
inter_if="${red}DOWN${nc}"
mgmt_if="${red}DOWN${nc}"
gateway="${red}NOT CONFIGURED${nc}"


if grep -q "up" /sys/class/net/public0/operstate; then

  public_if="${green}UP${nc}"
fi

if grep -q "up" /sys/class/net/private0/operstate; then

  private_if="${green}UP${nc}"
fi

if grep -q "up" /sys/class/net/inter0/operstate; then

  inter_if="${green}UP${nc}"
fi

if grep -q "up" /sys/class/net/mgmt0/operstate; then

  mgmt_if="${green}UP${nc}"

  if ip addr show mgmt0 | grep -q "$ipv6_gateway"; then

     gateway="${green}CONFIGURED${nc}"

  fi

fi

echo -e "Please review current status and configuration before proceeding:\n"
echo -e "PUBLIC INTERFACE: $public_if"
echo -e "PRIVATE INTERFACE: $private_if"
echo -e "INTER-REGION INTERFACE: $inter_if"
echo -e "MANAGEMENT INTERFACE: $mgmt_if"
echo -e "MANAGEMENT GATEWAY: $gateway\n"
read -p "Would you like to proceed and disable this PodNet? (y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

ip link set public0 down
ip link set private0 down
ip link set inter0 down
sudo ip addr del "$ipv6"10:0:1/64 dev mgmt0
primary_ipv4_subnet=$(echo "$json" | jq -r '.primary_ipv4_subnet')
IFS='/' read -r pms mask <<< "$primary_ipv4_subnet"
pms2=${pms%.*}.$((${pms##*.}+1))
sudo ip addr del "$pms2"/"$mask" dev mgmt0

#using oob to modify json since mgmt might be down
if ip addr show oob0 | grep --quiet 10."$pod_number".0.254; then

   jq '.podnet_a_enable=false' configs/config.json > tmp.$$.json && mv tmp.$$.json configs/config.json

   ssh -T pat@10."$pod_number".0.253 -i /home/pat/.ssh/id_rsa_"$pod_number"<<EOL

      jq ".podnet_a_enable=false" /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.>

   EOL

elif ip addr show oob0 | grep --quiet 10."$pod_number".0.253; then

   jq '.podnet_b_enable=false' configs/config.json > tmp.$$.json && mv tmp.$$.json configs/config.json

   ssh -T pat@10."$pod_number".0.254 -i /home/pat/.ssh/id_rsa_"$pod_number"<<EOL

      jq ".podnet_b_enable=false" /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.>

   EOL

fi

echo "This podnet has been disabled"


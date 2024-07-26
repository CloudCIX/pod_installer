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

public_if="${green}UP${nc}"
private_if="${green}UP${nc}"
inter_if="${green}UP${nc}"
mgmt_if="${green}UP${nc}"
gateway="${green}CONFIGURED${nc}"


if grep -q "down" /sys/class/net/public0/operstate; then

  public_if="${red}DOWN${nc}"
fi

if grep -q "down" /sys/class/net/private0/operstate; then

  private_if="${red}DOWN${nc}"
fi

if grep -q "down" /sys/class/net/inter0/operstate; then

  inter_if="${red}DOWN${nc}"
fi

if grep -q "down" /sys/class/net/mgmt0/operstate; then

  mgmt_if="${red}DOWN${nc}"
  gateway="${red}NOT CONFIGURED${nc}"

fi

echo -e "Please review current status and configuration before proceeding:\n"
echo -e "PUBLIC INTERFACE: $public_if"
echo -e "PRIVATE INTERFACE: $private_if"
echo -e "INTER-REGION INTERFACE: $inter_if"
echo -e "MANAGEMENT INTERFACE: $mgmt_if"
echo -e "MANAGEMENT GATEWAY: $gateway\n"
read -p "Would you like to proceed? (y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

ip link set public0 up
ip link set private0 up
ip link set inter0 up
ip link set mgmt0 up
sudo ip addr add "$ipv6"10:0:1/64 dev mgmt0
primary_ipv4_subnet=$(echo "$json" | jq -r '.primary_ipv4_subnet')
IFS='/' read -r pms mask <<< "$primary_ipv4_subnet"
pms2=${pms%.*}.$((${pms##*.}+1))
sudo ip addr add "$pms2"/"$mask" dev mgmt0

#assuming mgmt is up since we are enabling
if ip addr show mgmt0 | grep --quiet "$ipv6"10:0:2; then

   jq '.podnet_a_enable=true' /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.json

   echo "${green}Modified local config.json successfully{nc}"

   ssh -T pat@"$ipv6"10:0:3 -i /home/pat/.ssh/id_rsa_"$pod_number"<<EOL

      jq ".podnet_a_enable=true" /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.json

   EOL

   ssh_exit_code=$(echo $?)

   if [[ $ssh_exit_code == 0 ]]; then

      echo "${green}Modified remote config.json successfully{nc}"

   else

      echo "${red}Failed to modifiy remote config.json, please modify manually{nc}"

   fi


elif ip addr show mgmt0 | grep --quiet "$ipv6"10:0:3; then

   jq '.podnet_b_enable=true' /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.json

   echo "${green}Modified local config.json successfully {nc}"

   ssh -T pat@"$ipv6"10:0:2 -i /home/pat/.ssh/id_rsa_"$pod_number"<<EOL

      jq ".podnet_b_enable=true" /etc/cloudcix/pod/configs/config.json > /etc/cloudcix/pod/configs/tmp.$$.json && mv /etc/cloudcix/pod/configs/tmp.$$.json /etc/cloudcix/pod/configs/config.json

   EOL

   ssh_exit_code=$(echo $?)

   if [[ $ssh_exit_code == 0 ]]; then

      echo "${green}Modified remote config.json successfully{nc}"

   else

      echo "${red}Failed to modifiy remote config.json, please modify manually{nc}"

   fi

fi

echo "This podnet has been enabled"

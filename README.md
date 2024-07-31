# podnet_installer

Installer Tasks:

1 Network
  - 1.1 Public Interface setup
    - 1.1.1 Connect the Public Interface 
    - 1.1.2 Configure the Public Interface (call primitive)
  - 1.2 Management Interface setup
    - 1.2.1 Connect the Mgmt Interface 
    - 1.2.2 Configure the Mgmt Interface (call primitive)
  - 1.3 Private Interface setup
    - 1.3.1 Connect the Private Interface 
    - 1.3.2 Configure the Private Interface (call primitive)
  - 1.4 Inter Interface setup
    - 1.4.1 Connect the Inter Interface 
    - 1.4.2 Configure the Inter Interface (call primitive)
  - 1.5 HA Interface setup
    - 1.5.1 Connect the HA Interface 
    - 1.5.2 Configure the HA Interface with Vlan(44) tagged Interface  (call primitive)

2 Update config.json
  - 2.1 Update Interface names
    - 2.1.1 Find logical interface name for preconfigured default Interface of the host
    - 2.1.2 Create dictionary for all interfaces on host

3 Firewall 
  - 3.1 Prepare Firewall rules
    - 3.1.1 Inbound Rules IPv4
    - 3.1.2 Inbound Rules IPv6
    - 3.1.3 Forward Rules IPv4
    - 3.1.4 Forward Rules IPv6
    - 3.1.5 Outbound Rules IPv4
    - 3.1.6 Outbound Rules IPv6           
  - 3.2 Configure Firewall rules
    - 3.3.1 Call Primitive (call primitive)

4 RoboSOC
  - 4.1 Setup robosoc cron job
  
5 Docker Setup
  - 5.1 Download the docker-compose.yml file from GitHub
  - 5.2 Download nginx1.conf.template and nginx2.conf.template files from GitHub (cop)
  - 5.3 Starting Docker containers
  - 5.4 Setup Cron job for User expiration notifications (cop)
  - 5.5 Setup Cron job for backing up pgsqlapi database (cop)
  - 5.6 Configure passwordless access for robot user to PodNet A (region)
  - 5.7 Configure passwordless access for robot user to PodNet B (region)
  - 5.8 Delete `pat` user's SSH key pair on Appliance (region blend)

6 - 7 Reserved


8 Reset Routes
  - 8.1 Configure the Management IPv4 default(0.0.0.0/0) route to pms1
  - 8.2 Configure the Management IPv6 default(::/0) route to ::10:0:1
  
9 Communicate back to PAT(Non-PAT Pods)
  - 9.1 Logical names of PodNet/Appliance Interfaces

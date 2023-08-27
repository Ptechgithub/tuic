#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# Determine the system and define the system installation dependency mode
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "Note: Please run the script under the root user" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "Does not support the current VPS system, please use the mainstream operating system！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

archAffix(){
    case "$(uname -m)" in
        x86_64 | amd64 ) echo 'amd64' ;;
        armv8 | arm64 | aarch64 ) echo 'arm64' ;;
        * ) red "Unsupported CPU architecture! " && exit 1 ;;
    esac
}

realip(){
    ip=$(curl -s4m8 ip.p3terx.com -k | sed -n 1p) || ip=$(curl -s6m8 ip.p3terx.com -k | sed -n 1p)
}

insttuic(){
    warpv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE}
    fi
    ${PACKAGE_INSTALL} wget curl sudo

    wget https://gitlab.com/Misaka-blog/tuic-script/-/raw/main/files/tuic-server-latest-linux-$(archAffix) -O /usr/local/bin/tuic
    if [[ -f "/usr/local/bin/tuic" ]]; then
        chmod +x /usr/local/bin/tuic
    else
        red "Tuic kernel installation failed！"
        exit 1
    fi
    
    green "The methods for Get certificates ："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Script automatic ${YELLOW}（default）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Custom Certificate Path"
    echo ""
    read -rp "Please enter options [1-2]: " certInput
    if [[ $certInput == 2 ]]; then
        read -p "Please enter the path of (crt) file ：" cert_path
        yellow "Path of (crt) ：$cert_path "
        read -p "Please enter the path of the (key) file ：" key_path
        yellow "Path of (key) ：$key_path "
        read -p "Enter Domain name to get certificates ：" domain
        yellow "Your domain ：$domain"
    else
        cert_path="/root/cert.crt"
        key_path="/root/private.key"
        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "Original domain name detected: $domain's certificate is being applied"
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                ip=$(curl -s4m8 ip.p3terx.com -k | sed -n 1p) || ip=$(curl -s6m8 ip.p3terx.com -k | sed -n 1p)
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                ip=$(curl -s4m8 ip.p3terx.com -k | sed -n 1p) || ip=$(curl -s6m8 ip.p3terx.com -k | sed -n 1p)
            fi
            
            read -p "Please enter the domain name ：" domain
            [[ -z $domain ]] && red "No domain name entered, unable to perform operation！" && exit 1
            green "Domain name entered:  $domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo $domain > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "The certificate (cer.crt) and private key (private.key) files applied by the script ----> saved to the /root folder"
                    yellow "crt path: /root/cert.crt"
                    yellow "key path: /root/private.key"
                fi
            else
                red "The IP of the current domain name resolution does not match the real IP used by the current VPS"
                green "suggestions : "
                yellow "1. Make sure proxy of CloudFlare is turned off (DNS only), other domain name resolution or CDN website settings are the same"
                yellow "2. Please check whether the IP set by DNS resolution is the real IP of the VPS"
                yellow "3. The script may not keep up with the times, it is recommended to post screenshots to GitHub Issues or TG"
            fi
        fi
    fi

    read -p "Enter Port [1-65535]（Enter for random port）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} The port is already occupied by another program, please change the port and try again"
            read -p "Enter Port [1-65535]（Enter fo random port）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done
    yellow "The Port was set to：$port"

    read -p "Set UUID（Enter for generate UUID）：" uuid
    [[ -z $uuid ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
    yellow "UUID set to：$uuid"

    read -p "Enter Password（Enter for random）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "Password set to ：$passwd"

    green "Configuring Tuic..."
    mkdir /etc/tuic >/dev/null 2>&1
    cat << EOF > /etc/tuic/tuic.json
{
    "server": "[::]:$port",
    "users": {
        "$uuid": "$passwd"
    },
    "certificate": "$cert_path",
    "private_key": "$key_path",
    "congestion_control": "bbr",
    "alpn": ["h3"],
    "log_level": "warn"
}
EOF

    mkdir /root/tuic >/dev/null 2>&1
    cat << EOF > /root/tuic/tuic-client.json
{
    "relay": {
        "server": "$domain:$port",
        "uuid": "$uuid",
        "password": "$passwd",
        "ip": "$ip",
        "congestion_control": "bbr",
        "alpn": ["h3"]
    },
    "local": {
        "server": "127.0.0.1:6080"
    },
    "log_level": "warn"
}
EOF
    cat << EOF > /root/tuic/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114

proxies:
  - name: Peyman-tuic
    server: $domain
    port: $port
    type: tuic
    uuid: $uuid
    password: $passwd
    ip: $ip
    alpn: [h3]
    disable-sni: true
    reduce-rtt: true
    request-timeout: 8000
    udp-relay-mode: quic
    congestion-controller: bbr

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Peyman-tuic
      
rules:
  - GEOIP,IR,DIRECT
  - MATCH,Proxy
EOF

    cat << EOF >/etc/systemd/system/tuic.service
[Unit]
Description=tuic Service
Documentation=https://gitlab.com/Ptechgithub/tuic
After=network.target
[Service]
User=root
ExecStart=/usr/local/bin/tuic -c /etc/tuic/tuic.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
    echo "tuic://$uuid:$passwd@$domain:$port/?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&allow_insecure=1#Peyman-Tuic" > /root/tuic/tuic.txt
    
    systemctl daemon-reload
    systemctl enable tuic
    systemctl start tuic
    if [[ -n $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/etc/tuic/tuic.json' ]]; then
        green "The tuic service started successfully"
    else
        red "The tuic service failed to start. Please run systemctl status tuic to view the service status and give feedback. The script exits" && exit 1
    fi
    red "======================================================================================"
    green "Tuic proxy service installation complete"
    yellow "The content of the client configuration file tuic-client.json saved to /root/tuic/tuic-client.json"
    cat /root/tuic/tuic-client.json
    yellow "Clash Meta Client profile saved to /root/tuic/clash-meta.yaml"
    yellow "The nekobox configuration as follows and saved to /root/tuic/tuic.txt"
    cat /root/tuic/tuic.txt
}

unsttuic(){
    systemctl stop tuic
    systemctl disable tuic
    rm -f /etc/systemd/system/tuic.service /root/tuic.sh
    rm -rf /usr/local/bin/tuic /etc/tuic /root/tuic
    
    green "Tuic has been completely uninstalled！"
}

starttuic(){
    systemctl start tuic
    systemctl enable tuic >/dev/null 2>&1
}

stoptuic(){
    systemctl stop tuic
    systemctl disable tuic >/dev/null 2>&1
}

tuicswitch(){
    yellow "Please choose ："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Start Tuic"
    echo -e " ${GREEN}2.${PLAIN} Stop Tuic"
    echo -e " ${GREEN}3.${PLAIN} Restart Tuic"
    echo ""
    read -rp "please enter options [0-3]: " switchInput
    case $switchInput in
        1 ) starttuic ;;
        2 ) stoptuic ;;
        3 ) stoptuic && starttuic ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/tuic/tuic.json 2>/dev/null | sed -n 2p | awk '{print $2}' | tr -d ',' | awk -F ":" '{print $4}' | tr -d '"')
    
    read -p "Enter Port [1-65535]（Enter fo random port）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} The port is already occupied by another program, please change the port and try again"
            read -p "Enter Port [1-65535]（Enter fo random port）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "2s/$oldport/$port/g" /etc/tuic/tuic.json
    sed -i "3s/$oldport/$port/g" /root/tuic/tuic-client.json
    sed -i "4s/$oldport/$port/g" /root/tuic/tuic.txt
    sed -i "19s/$oldport/$port/g" /root/tuic/clash-meta.yaml

    stoptuic && starttuic

    green "The port has been successfully modified to：$port"
    yellow "Please manually update the client configuration file to use node"
    showconf
}

changeuuid(){
    olduuid=$(cat /etc/tuic/tuic.json 2>/dev/null | sed -n 4p | awk '{print $1}' | tr -d ':"')

    read -p "Set UUID（Enter for generate UUID）：" uuid
    [[ -z $uuid ]] && uuid=$(cat /proc/sys/kernel/random/uuid)

    sed -i "3s/$olduuid/$uuid/g" /etc/tuic/tuic.json
    sed -i "4s/$olduuid/$uuid/g" /root/tuic/tuic-client.json
    sed -i "5s/$olduuid/$uuid/g" /root/tuic/tuic.txt
    sed -i "21s/$olduuid/$uuid/g" /root/tuic/clash-meta.yaml

    stoptuic && starttuic

    green "The UUID has been successfully modified to：$uuid"
    yellow "Please manually update the client configuration file to use node"
    showconf
}

changepasswd(){
    oldpasswd=$(cat /etc/tuic/tuic.json 2>/dev/null | sed -n 4p | awk '{print $2}' | tr -d '"')

    read -p "Enter Password（Enter for random）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "3s/$oldpasswd/$passwd/g" /etc/tuic/tuic.json
    sed -i "5s/$oldpasswd/$passwd/g" /root/tuic/tuic-client.json
    sed -i "6s/$oldpasswd/$passwd/g" /root/tuic/tuic.txt
    sed -i "22s/$oldpasswd/$passwd/g" /root/tuic/clash-meta.yaml

    stoptuic && starttuic

    green "The password has been successfully changed to：$passwd"
    yellow "Please manually update the client configuration file to use node"
    showconf
}

changeconf(){
    green "configuration options : "
    echo -e " ${GREEN}1.${PLAIN} Change Port"
    echo -e " ${GREEN}2.${PLAIN} Change UUID"
    echo -e " ${GREEN}3.${PLAIN} Change Password"
    echo ""
    read -p " Please select an option [1-3]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changeuuid ;;
        3 ) changepasswd ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "The content of the client configuration file tuic-client.json saved to /root/tuic/tuic-client.json"
    cat /root/tuic/tuic-client.json
    yellow "Clash Meta client configuration file saved to /root/tuic/clash-meta.yaml"
    yellow "Tuic node configuration plaintext saved to /root/tuic/tuic.txt"
    cat /root/tuic/tuic.txt
}

menu() {
    clear
    echo "##########################################################"
    echo -e "#          ${RED}Tuic 一one-click installation script${PLAIN}          #"
    echo -e "# ${GREEN}Gihub ${PLAIN}: https://gitlab.com/Ptechgithub                 #"
    echo -e "# ${GREEN}Telegram ${PLAIN}: https://t.me/P_tech2024                     #"
    echo -e "# ${GREEN}YouTube ${PLAIN}: https://www.youtube.com/@IR_TECH             #"
    echo "##########################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Install Tuic"
    echo -e " ${GREEN}2.${PLAIN} ${RED}Uninstall Tuic${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} Turn off/on/Restart "
    echo -e " ${GREEN}4.${PLAIN} Modify configuration"
    echo -e " ${GREEN}5.${PLAIN} Show Tuic Config"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} exit script"
    echo ""
    read -rp "please enter options [0-5]: " menuInput
    case $menuInput in
        1 ) insttuic ;;
        2 ) unsttuic ;;
        3 ) tuicswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        * ) exit 1 ;;
    esac
}

menu
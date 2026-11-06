SERVICE_NAME="vlan_ts"
source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/ut_plat.sh


SELF_NAME="`basename "$0"`"

service_start() {
        vlan_pvt=`syscfg get vlan_id_pvt`
        vlan_mesh=`syscfg get vlan_id_mesh`
        vlan_iot=`syscfg get vlan_id_iot`

        echo "service_start : START" >> /tmp/abc.txt

        ip link set brlan0 type bridge vlan_filtering 1
        bridge vlan add dev wifi0 vid $vlan_pvt pvid untagged
        bridge vlan add dev wifi0.1 vid $vlan_mesh pvid untagged
        bridge vlan add dev wifi0.2 vid $vlan_iot pvid untagged
        bridge vlan add dev wifi1 vid $vlan_pvt pvid untagged
        bridge vlan add dev wifi1.1 vid $vlan_mesh pvid untagged
        bridge vlan add dev wifi1.2 vid $vlan_iot pvid untagged
        bridge vlan add dev wifi2 vid $vlan_pvt pvid untagged
        bridge vlan add dev wifi2.1 vid $vlan_mesh pvid untagged
        bridge vlan add dev wifi2.2 vid $vlan_iot pvid untagged
        bridge vlan add dev mld0 vid $vlan_pvt pvid untagged

        ip link add link brlan0 name brlan0.$vlan_pvt type vlan id $vlan_pvt
        ip link add link brlan0 name brlan0.$vlan_mesh type vlan id $vlan_mesh
        ip link add link brlan0 name brlan0.$vlan_iot type vlan id $vlan_iot

        bridge vlan add dev brlan0 vid $vlan_pvt self
        bridge vlan add dev brlan0 vid $vlan_mesh self
        bridge vlan add dev brlan0 vid $vlan_iot self

        ifconfig brlan0.$vlan_pvt  192.168.13.1 netmask 255.255.255.0 up
        ifconfig brlan0.$vlan_mesh 192.168.14.1 netmask 255.255.255.0 up
        ifconfig brlan0.$vlan_iot  192.168.15.1 netmask 255.255.255.0 up

        iptables -I FORWARD -i brlan0.$vlan_pvt -o brlan0.$vlan_mesh -j DROP
        iptables -I FORWARD -i brlan0.$vlan_mesh -o brlan0.$vlan_pvt -j DROP

        iptables -I FORWARD -i brlan0.$vlan_mesh -o brlan0.$vlan_iot -j DROP
        iptables -I FORWARD -i brlan0.$vlan_iot -o brlan0.$vlan_mesh -j DROP

        iptables -I FORWARD -i brlan0.$vlan_pvt -o brlan0.$vlan_iot -j DROP
        iptables -I FORWARD -i brlan0.$vlan_iot -o brlan0.$vlan_pvt -j DROP

	iptables -I INPUT -i brlan0.$vlan_pvt  -p udp --dport 67:68 -j ACCEPT
	iptables -I INPUT -i brlan0.$vlan_pvt  -p udp --sport 67:68 -j ACCEPT
	iptables -I INPUT -i brlan0.$vlan_mesh -p udp --dport 67:68 -j ACCEPT
	iptables -I INPUT -i brlan0.$vlan_mesh -p udp --sport 67:68 -j ACCEPT
	iptables -I INPUT -i brlan0.$vlan_iot  -p udp --dport 67:68 -j ACCEPT
	iptables -I INPUT -i brlan0.$vlan_iot  -p udp --sport 67:68 -j ACCEPT

        echo "interface=brlan0.$vlan_pvt" >> /var/dnsmasq.conf
        echo "dhcp-range=192.168.13.2,192.168.13.253,255.255.255.0,7d" >> /var/dnsmasq.conf
        echo "interface=brlan0.$vlan_mesh" >> /var/dnsmasq.conf
        echo "dhcp-range=192.168.14.2,192.168.14.253,255.255.255.0,7d" >> /var/dnsmasq.conf
        echo "interface=brlan0.$vlan_iot" >> /var/dnsmasq.conf
        echo "dhcp-range=192.168.15.2,192.168.15.253,255.255.255.0,7d" >> /var/dnsmasq.conf

        killall dnsmasq
        dnsmasq -P 4096 -C /var/dnsmasq.conf --dhcp-authoritative
}

service_stop () {
        ip link set brlan0 type bridge vlan_filtering 1

        vlan_pvt=`syscfg get vlan_id_pvt`
        vlan_mesh=`syscfg get vlan_id_mesh`
        vlan_iot=`syscfg get vlan_id_iot`

        echo "service_stop : START " >> /tmp/abc.txt

        bridge vlan del vid $vlan_pvt dev wifi0
        bridge vlan del vid $vlan_mesh dev wifi0.1
        bridge vlan del vid $vlan_iot dev wifi0.2
        bridge vlan del vid $vlan_pvt dev wifi1
        bridge vlan del vid $vlan_mesh dev wifi1.1
        bridge vlan del vid $vlan_iot dev wifi1.2
        bridge vlan del vid $vlan_pvt dev wifi2
        bridge vlan del vid $vlan_mesh dev wifi2.1
        bridge vlan del vid $vlan_iot dev wifi2.2
        bridge vlan del vid $vlan_pvt dev mld0

        bridge vlan del dev brlan0 vid $vlan_pvt self
        bridge vlan del dev brlan0 vid $vlan_mesh self
        bridge vlan del dev brlan0 vid $vlan_iot self

        ip link del link brlan0 name brlan0.$vlan_pvt type vlan id $vlan_pvt
        ip link del link brlan0 name brlan0.$vlan_mesh type vlan id $vlan_mesh
        ip link del link brlan0 name brlan0.$vlan_iot type vlan id $vlan_iot

        bridge vlan del vid 1 dev wifi0
        bridge vlan del vid 1 dev wifi0.1
        bridge vlan del vid 1 dev wifi0.2
        bridge vlan del vid 1 dev wifi1.2
        bridge vlan del vid 1 dev wifi1.1
        bridge vlan del vid 1 dev wifi1
        bridge vlan del vid 1 dev wifi2
        bridge vlan del vid 1 dev wifi2.1
        bridge vlan del vid 1 dev wifi2.2
        bridge vlan del vid 1 dev mld0

        sed -i '/brlan0./d' /var/dnsmasq.conf
        sed -i '/brlan0./d' /var/dnsmasq.conf
        sed -i '/brlan0./d' /var/dnsmasq.conf

        sed -i '/192.168.13.2/d' /var/dnsmasq.conf
        sed -i '/192.168.14.2/d' /var/dnsmasq.conf
        sed -i '/192.168.15.2/d' /var/dnsmasq.conf

        killall dnsmasq
        dnsmasq -P 4096 -C /var/dnsmasq.conf --dhcp-authoritative

        iptables -D FORWARD -i brlan0.$vlan_pvt -o brlan0.$vlan_mesh -j DROP
        iptables -D FORWARD -i brlan0.$vlan_mesh -o brlan0.$vlan_pvt -j DROP

        iptables -D FORWARD -i brlan0.$vlan_mesh -o brlan0.$vlan_iot -j DROP
        iptables -D FORWARD -i brlan0.$vlan_iot -o brlan0.$vlan_mesh -j DROP

        iptables -D FORWARD -i brlan0.$vlan_pvt -o brlan0.$vlan_iot -j DROP
        iptables -D FORWARD -i brlan0.$vlan_iot -o brlan0.$vlan_pvt -j DROP

        iptables -D INPUT -i brlan0.$vlan_pvt -p udp --dport 67:68 -j ACCEPT
        iptables -D INPUT -i brlan0.$vlan_pvt -p udp --sport 67:68 -j ACCEPT
        iptables -D INPUT -i brlan0.$vlan_mesh -p udp --dport 67:68 -j ACCEPT
        iptables -D INPUT -i brlan0.$vlan_mesh -p udp --sport 67:68 -j ACCEPT
        iptables -D INPUT -i brlan0.$vlan_iot -p udp --dport 67:68 -j ACCEPT
        iptables -D INPUT -i brlan0.$vlan_iot -p udp --sport 67:68 -j ACCEPT
}


service_init() {
        echo "service_init : START " >> /tmp/abc.txt
}

#---------------------------------------------------------------

service_init

case "$1" in
      start)
      service_start
      ;;
      stop)
      service_stop
      ;;
      restart)
      service_stop
      service_start
      ;;
   *)
      echo "Usage: $SERVICE_NAME [ start | stop | restart]" > /dev/console
      exit 3
      ;;
esac


#!/bin/sh

action="$1"
storage_Path="/etc/storage"
smartdns_Bin="/usr/bin/smartdns"
smartdns_Ini="$storage_Path/smartdns_conf.ini"
smartdns_Conf="$storage_Path/smartdns.conf"
smartdns_tmp_Conf="$storage_Path/smartdns_tmp.conf"
smartdns_address_Conf="$storage_Path/smartdns_address.conf"
smartdns_blacklist_Conf="$storage_Path/smartdns_blacklist-ip.conf"
smartdns_whitelist_Conf="$storage_Path/smartdns_whitelist-ip.conf"
smartdns_custom_Conf="$storage_Path/smartdns_custom.conf"
dnsmasq_Conf="$storage_Path/dnsmasq/dnsmasq.conf"
chn_Route="$storage_Path/chinadns/chnroute.txt"

sdns_enable=$(nvram get sdns_enable)
snds_name=$(nvram get snds_name)
sdns_port=$(nvram get sdns_port)
sdns_tcp_server=$(nvram get sdns_tcp_server)
sdns_ipv6_server=$(nvram get sdns_ipv6_server)
snds_ip_change=$(nvram get snds_ip_change)
sdns_ipv6=$(nvram get sdns_ipv6)
sdns_www=$(nvram get sdns_www)
sdns_exp=$(nvram get sdns_exp)
snds_redirect=$(nvram get snds_redirect)
sdns_cache_persist=$(nvram get sdns_cache_persist)
snds_cache=$(nvram get snds_cache)
sdns_ttl=$(nvram get sdns_ttl)
sdns_ttl_min=$(nvram get sdns_ttl_min)
sdns_ttl_max=$(nvram get sdns_ttl_max)
sdnse_enable=$(nvram get sdnse_enable)
sdnse_port=$(nvram get sdnse_port)
sdnse_tcp=$(nvram get sdnse_tcp)
sdnse_speed=$(nvram get sdnse_speed)
sdns_speed=$(nvram get sdns_speed)
sdnse_name=$(nvram get sdnse_name)
sdnse_address=$(nvram get sdnse_address)
sdns_address=$(nvram get sdns_address)
sdnse_ns=$(nvram get sdnse_ns)
sdns_ns=$(nvram get sdns_ns)
sdnse_ipset=$(nvram get sdnse_ipset)
sdns_ipset=$(nvram get sdns_ipset)
sdnse_as=$(nvram get sdnse_as)
sdns_as=$(nvram get sdns_as)
sdnse_ipc=$(nvram get sdnse_ipc)
sdnse_cache=$(nvram get sdnse_cache)
ss_white=$(nvram get ss_white)
ss_black=$(nvram get ss_black)
sdns_coredump=$(nvram get sdns_coredump)


check_ss(){
if [ $(nvram get ss_enable) = 1 ] && [ $(nvram get ss_run_mode) = "router" ] && [ $(nvram get pdnsd_enable) = 0 ]; then
logger -t "SmartDNS" "系统检测到SS模式为绕过大陆模式，并且启用了pdnsd,请先调整SS解析使用SmartDNS+手动配置模式！程序将退出。"
nvram set sdns_enable=0
exit 0
fi
}

get_tz()
{
	SET_TZ=""
	for tzfile in /etc/TZ
	do
		if [ ! -e "$tzfile" ]; then
			continue
		fi		
		tz="`cat $tzfile 2>/dev/null`"
	done	
	if [ -z "$tz" ]; then
		return	
	fi	
	SET_TZ=$tz
}

Get_sdns_conf () {
    # 【】
    :>"$smartdns_tmp_Conf"
    echo "server-name $snds_name" >> "$smartdns_tmp_Conf"
    ARGS_1=""
    if [ "$sdns_address" = "1" ] ; then
     ARGS_1="$ARGS_1 -no-rule-addr"
    fi
    if [ "$sdns_ns" = "1" ] ; then
        ARGS_1="$ARGS_1 -no-rule-nameserver"
    fi
    if [ "$sdns_ipset" = "1" ] ; then
        ARGS_1="$ARGS_1 -no-rule-ipset"
    fi
    if [ "$sdns_speed" = "1" ] ; then
        ARGS_1="$ARGS_1 -no-speed-check"
    fi
    if [ "$sdns_as" = "1" ] ; then
        ARGS_1="$ARGS_1 -no-rule-soa"
    fi
    if [ "$sdns_ipv6_server" = "1" ] ; then
        echo "bind" "[::]:$sdns_port $ARGS_1" >> "$smartdns_tmp_Conf"
    else
        echo "bind" ":$sdns_port $ARGS_1" >> "$smartdns_tmp_Conf"
    fi
    if [ "$sdns_tcp_server" = "1" ] ; then
        if [ "$sdns_ipv6_server" = "1" ] ; then
            echo "bind-tcp" "[::]:$sdns_port $ARGS_1" >> "$smartdns_tmp_Conf"
        else
            echo "bind-tcp" ":$sdns_port $ARGS_1" >> "$smartdns_tmp_Conf"
        fi
    fi
    # 读取 第二服务器 配置
    Get_sdnse_conf
    echo "cache-size $snds_cache" >> "$smartdns_tmp_Conf"
    echo "rr-ttl $sdns_ttl" >> "$smartdns_tmp_Conf"
    echo "rr-ttl-min $sdns_ttl_min" >> "$smartdns_tmp_Conf"
    echo "rr-ttl-max $sdns_ttl_max" >> "$smartdns_tmp_Conf"
    echo "tcp-idle-time 120" >> "$smartdns_tmp_Conf"
    if [ "$snds_ip_change" -eq 1 ] ;then
        echo "dualstack-ip-selection yes" >> "$smartdns_tmp_Conf"
        echo "dualstack-ip-selection-threshold $(nvram get snds_ip_change_time)" >> "$smartdns_tmp_Conf"
    elif [ "$sdns_ipv6" -eq 1 ] ;then
        echo "force-AAAA-SOA yes" >> "$smartdns_tmp_Conf"
    fi
    if [ "$sdns_cache_persist" -eq 1 ] && [ "$snds_cache" -gt 0 ] ;then
        echo "cache-persist yes" >> "$smartdns_tmp_Conf"
        echo "cache-file /etc/storage/smartdns.cache" >> "$smartdns_tmp_Conf"    
    else
        echo "cache-persist no" >> "$smartdns_tmp_Conf"
    fi
    if [ "$sdns_www" -eq 1 ] && [ " $snds_cache" -gt 0 ] ;then
        echo "prefetch-domain yes" >> "$smartdns_tmp_Conf"
    else
        echo "prefetch-domain no" >> "$smartdns_tmp_Conf"
    fi
    if [ "$sdns_exp" -eq 1 ] && [ "$snds_cache" -gt 0 ] ;then
        echo "serve-expired yes" >> "$smartdns_tmp_Conf"
    else
        echo "serve-expired no" >> "$smartdns_tmp_Conf"
    fi
#    echo "log-level warn" >> "$smartdns_tmp_Conf"
    listnum=$(nvram get sdnss_staticnum_x)
    for i in $(seq 1 "$listnum")
    do
        j=$(expr "$i" - 1)
        sdnss_enable=$(nvram get sdnss_enable_x"$j")
        if  [ "$sdnss_enable" -eq 1 ] ; then
            sdnss_name=$(nvram get sdnss_name_x"$j")
            sdnss_ip=$(nvram get sdnss_ip_x"$j")
            sdnss_port=$(nvram get sdnss_port_x"$j")
            sdnss_type=$(nvram get sdnss_type_x"$j")
            sdnss_ipc=$(nvram get sdnss_ipc_x"$j")
            sdnss_named=$(nvram get sdnss_named_x"$j")
            sdnss_non=$(nvram get sdnss_non_x"$j")
            sdnss_ipset=$(nvram get sdnss_ipset_x"$j")
            ipc=""
            named=""
            non=""
            sipset=""
            if [ "$sdnss_ipc" = "whitelist" ] ; then
                ipc="-whitelist-ip"
            elif [ "$sdnss_ipc" = "blacklist" ] ; then
                ipc="-blacklist-ip"
            fi
            if [ "$sdnss_named"x != x ] ; then
                named="-group $sdnss_named"
            fi
            if [ "$sdnss_non" = "1" ] ; then
                non="-exclude-default-group"
            fi
            if [ "$sdnss_type" = "tcp" ] ; then
                if [ "$sdnss_port" = "default" ] ; then
                    echo "server-tcp $sdnss_ip:53 $ipc $named $non" >> "$smartdns_tmp_Conf"
                else
                    echo "server-tcp $sdnss_ip:$sdnss_port $ipc $named $non" >> "$smartdns_tmp_Conf"
                fi
            elif [ "$sdnss_type" = "udp" ] ; then
                if [ "$sdnss_port" = "default" ] ; then
                    echo "server $sdnss_ip:53 $ipc $named $non" >> "$smartdns_tmp_Conf"
                else
                    echo "server $sdnss_ip:$sdnss_port $ipc $named $non" >> "$smartdns_tmp_Conf"
                fi
            elif [ "$sdnss_type" = "tls" ] ; then
                if [ "$sdnss_port" = "default" ] ; then
                    echo "server-tls $sdnss_ip:853 $ipc $named $non" >> "$smartdns_tmp_Conf"
                else
                    echo "server-tls $sdnss_ip:$sdnss_port $ipc $named $non" >> "$smartdns_tmp_Conf"
                fi
            elif [ "$sdnss_type" = "https" ] ; then
                if [ "$sdnss_port" = "default" ] ; then
                    echo "server-https $sdnss_ip:443 $ipc $named $non" >> "$smartdns_tmp_Conf"
                else
                    echo "server-https $sdnss_ip:$sdnss_port $ipc $named $non" >> "$smartdns_tmp_Conf"
                fi    
            fi
            if [ "$sdnss_ipset"x != x ] ; then
                # 调用 check_ip_Addr 函数，检测 ip 是否合规
                Check_ip_addr "$sdnss_ipset"
                if [ "$?" = "1" ] ;then
                    echo "ipset /$sdnss_ipset/smartdns" >> "$smartdns_tmp_Conf"
                else
                    ipset add smartdns "$sdnss_ipset" 2>/dev/null
                fi
            fi
        fi
    done
    if [ "$ss_white" = "1" ] && [ -f "$chn_Route" ] ; then
        :>/tmp/whitelist.conf
        logger -t "SmartDNS" "开始处理白名单IP"
        awk '{printf("whitelist-ip %s\n", $1, $1 )}' "$chn_Route" >> /tmp/whitelist.conf
        echo "conf-file /tmp/whitelist.conf" >> "$smartdns_tmp_Conf"
    fi
    if [ "$ss_black" = "1" ] && [ -f "$chn_Route" ] ; then
        :>/tmp/blacklist.conf
        logger -t "SmartDNS" "开始处理黑名单IP"
        awk '{printf("blacklist-ip %s\n", $1, $1 )}' "$chn_Route" >> /tmp/blacklist.conf
        echo "conf-file /tmp/blacklist.conf" >> "$smartdns_tmp_Conf"
    fi
}


Get_sdnse_conf () {
    # 【】
    if [ "$sdnse_enable" -eq 1 ] ; then
    ARGS_2=""
    ADDR=""
    if [ "$sdnse_speed" = "1" ] ; then
        ARGS_2="$ARGS_2 -no-speed-check"
    fi
    if [ -n "$sdnse_name" ] ; then
        ARGS_2="$ARGS_2-group $sdnse_name"
    fi
    if [ "$sdnse_address" = "1" ] ; then
        ARGS_2="$ARGS_2-no-rule-addr"
    fi
    if [ "$sdnse_ns" = "1" ] ; then
        ARGS_2="$ARGS_2-no-rule-nameserver"
    fi
    if [ "$sdnse_ipset" = "1" ] ; then
        ARGS_2="$ARGS_2-no-rule-ipset"
    fi
    if [ "$sdnse_as" = "1" ] ; then
        ARGS_2="$ARGS_2-no-rule-soa"
    fi
    if [ "$sdnse_ipc" = "1" ] ; then
        ARGS_2="$ARGS_2-no-dualstack-selection"
    fi
    if [ "$sdnse_cache" = "1" ] ; then
        ARGS_2="$ARGS_2-no-cache"
    fi
    if [ "$sdns_ipv6_server" = "1" ] ; then
        ADDR="[::]"
    else
        ADDR=""
    fi
    echo "bind" "$ADDR:$sdnse_port $ARGS_2" >> "$smartdns_tmp_Conf"
     if [ "$sdnse_tcp" = "1" ] ; then
        echo "bind-tcp" "$ADDR:$sdnse_port $ARGS_2" >> "$smartdns_tmp_Conf"
    fi
fi
}

change_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#$sdns_port
EOF
/sbin/restart_dhcpd
logger -t "SmartDNS" "添加DNS转发到$sdns_port端口"
}
del_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
/sbin/restart_dhcpd
}

set_iptable()
{
	ipv6_server=$1
	tcp_server=$2

	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		if [ "$tcp_server" == "1" ]; then
			iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
		fi
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
	done

	if [ "$ipv6_server" == 0 ]; then
		return
	fi

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		if [ "$tcp_server" == "1" ]; then
			ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
		fi
		ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
	done
logger -t "SmartDNS" "重定向53端口"
}

clear_iptable()
{
	local OLD_PORT="$1"
	local ipv6_server=$2
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	if [ "$ipv6_server" == 0 ]; then
		return
	fi

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
	
}

start_smartdns(){
rm -f /tmp/sdnsipset.conf
args=""
logger -t "SmartDNS" "创建配置文件."
ipset -N smartdns hash:net 2>/dev/null
gensmartconf

grep -v '^#' $smartdns_address_Conf | grep -v "^$" >> "$smartdns_tmp_Conf"
grep -v '^#' $smartdns_blacklist_Conf | grep -v "^$" >> "$smartdns_tmp_Conf"
grep -v '^#' $smartdns_whitelist_Conf | grep -v "^$" >> "$smartdns_tmp_Conf"
grep -v '^#' $smartdns_custom_Conf | grep -v "^$" >> "$smartdns_tmp_Conf"
sed -i '/my.router/d' "$smartdns_tmp_Conf"
echo "domain-rules " "/my.router/ -c none -a $IPS4 -d no" >> "$smartdns_tmp_Conf"
# 配置文件去重
awk '!x[$0]++' "$smartdns_tmp_Conf" > "$smartdns_Conf"
rm -f "$smartdns_tmp_Conf"
if [ "$sdns_coredump" = "1" ]; then
		args="$args -S"
	fi
	#get_tz
	#if [ ! -z "$SET_TZ" ]; then
#		procd_set_param env TZ="$SET_TZ"
	#fi
$smartdns_file -f -c $SMARTDNS_CONF $args &>/dev/null &
logger -t "SmartDNS" "SmartDNS启动成功"
if [ $snds_redirect = "2" ]; then
		set_iptable $sdns_ipv6_server $sdns_tcp_server
	elif [ $snds_redirect = "1" ]; then
		change_dns
	fi

}

CheckIPAddr()
{
echo $1|grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}$" > /dev/null;
#IP地址必须为全数字
        if [ $? -ne 0 ]
        then
                return 1
        fi
        ipaddr=$1
        a=`echo $ipaddr|awk -F . '{print $1}'`  #以"."分隔，取出每个列的值
        b=`echo $ipaddr|awk -F . '{print $2}'`
        c=`echo $ipaddr|awk -F . '{print $3}'`
        d=`echo $ipaddr|awk -F . '{print $4}'`
        for num in $a $b $c $d
        do
                if [ $num -gt 255 ] || [ $num -lt 0 ]    #每个数值必须在0-255之间
                then
                        return 1
                fi
        done
                return 0
}

stop_smartdns(){
rm -f /tmp/whitelist.conf
rm -f /tmp/blacklist.conf
smartdns_process=`pidof smartdns`
if [ -n "$smartdns_process" ];then 
	logger -t "SmartDNS" "关闭smartdns进程..."
	killall smartdns >/dev/null 2>&1
	kill -9 "$smartdns_process" >/dev/null 2>&1
fi
ipset -X smartdns 2>/dev/null
del_dns
clear_iptable $sdns_port $sdns_ipv6_server
if [ "$snds_redirect" = "2" ]; then
		clear_iptable $sdns_port $sdns_ipv6_server
	elif [ "$snds_redirect" = "1" ]; then
		del_dns
	fi
logger -t "SmartDNS" "SmartDNS已关闭"
}

case $1 in
start)
    check_ss
	start_smartdns
	;;
stop)
	stop_smartdns
	;;
*)
	echo "check"
	;;
esac
Main

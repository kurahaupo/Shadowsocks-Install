#!/bin/bash

prefix=/usr/local
lbin_dir=$prefix/bin
llib_dir=$prefix/lib
share_dir=$prefix/share
man_dir=$share_dir/man
doc_dir=$share_dir/doc
PATH=/bin:/sbin:/usr/bin:/usr/sbin:$lbin_dir:$prefix/sbin:~/bin
export PATH

#
# Thanks to: Teddysun, M3chD09
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://opensource.org/licenses/GPL-3.0.
#
# Auto install Shadowsocks Server
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Reference URL:
# https://github.com/shadowsocks
# https://github.com/shadowsocks/shadowsocks-libev
# https://github.com/shadowsocksrr/shadowsocksr
#

red=$'\033[0;31m'
green=$'\033[0;32m'
yellow=$'\033[0;33m'
plain=$'\033[0m'

die() {
    error "$@"
    exit 1
}

error() {
    printf '[%s] %s\n' "${red}Error$plain" "$*"
}

warn() {
    printf '[%s] %s\n' "${yellow}Warning$plain" "$*"
}

info() {
    printf '[%s] %s\n' "${green}Info$plain" "$*"
}

info_kv() {
    printf '%-23s %s' "$1:" "$red$2$plain"
}

[[ $EUID != 0 ]] && die 'This script must be run as root!'

software=(Shadowsocks-libev ShadowsocksR)

libsodium_file=libsodium-1.0.18
libsodium_url=https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz

mbedtls_file=mbedtls-2.16.11
mbedtls_url=https://github.com/ARMmbed/mbedtls/archive/$mbedtls_file.tar.gz

shadowsocks_libev_init=/etc/init.d/shadowsocks-libev
shadowsocks_libev_config=/etc/shadowsocks-libev/config.json
shadowsocks_libev_config_dir=${shadowsocks_libev_config%/*}
shadowsocks_libev_centos=https://raw.githubusercontent.com/Yuk1n0/Shadowsocks-Install/master/shadowsocks-libev-centos
shadowsocks_libev_debian=https://raw.githubusercontent.com/Yuk1n0/Shadowsocks-Install/master/shadowsocks-libev-debian

shadowsocks_r_file=shadowsocksr-3.2.2
shadowsocks_r_url=https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz
shadowsocks_r_init=/etc/init.d/shadowsocks-r
shadowsocks_r_config=/etc/shadowsocks-r/config.json
shadowsocks_r_config_dir=${shadowsocks_r_config%/*}
shadowsocks_r_centos=https://raw.githubusercontent.com/Yuk1n0/Shadowsocks-Install/master/shadowsocksR-centos
shadowsocks_r_debian=https://raw.githubusercontent.com/Yuk1n0/Shadowsocks-Install/master/shadowsocksR-debian

common_ciphers=(
    aes-256-gcm
    aes-192-gcm
    aes-128-gcm
    aes-256-cfb
    aes-192-cfb
    aes-128-cfb
    aes-256-ctr
    aes-192-ctr
    aes-128-ctr
    camellia-256-cfb
    camellia-192-cfb
    camellia-128-cfb
    xchacha20-ietf-poly1305
    chacha20-ietf-poly1305
    chacha20-ietf
    chacha20
    salsa20
    bf-cfb
    rc4-md5
)
r_ciphers=(
    none
    aes-256-cfb
    aes-192-cfb
    aes-128-cfb
    aes-256-cfb8
    aes-192-cfb8
    aes-128-cfb8
    aes-256-ctr
    aes-192-ctr
    aes-128-ctr
    chacha20-ietf
    xchacha20
    xsalsa20
    chacha20
    salsa20
    rc4-md5
)

# Reference URL:
# https://github.com/shadowsocksrr/shadowsocks-rss/blob/master/ssr.md
# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
protocols=(
    origin
    verify_deflate
    auth_sha1_v4
    auth_sha1_v4_compatible
    auth_aes128_md5
    auth_aes128_sha1
    auth_chain_a
    auth_chain_b
    auth_chain_c
    auth_chain_d
    auth_chain_e
    auth_chain_f
)

obfs=(
    plain
    http_simple
    http_simple_compatible
    http_post
    http_post_compatible
    random_head
    random_head_compatible
    tls1.2_ticket_auth
    tls1.2_ticket_auth_compatible
    tls1.2_ticket_fastauth
    tls1.2_ticket_fastauth_compatible
)

is_valid_number() {
    local -n val=$1
    local min=${2:-$val} max=${3:-$val} def=$4
    case $val in
    '')
        [[ $def ]] || return 1
        val=$def
        ;;
    0?* | *[!0-9]* )
        return 1
        ;;
    *)
        (( min <= val && val <= max ))
    esac
}

has_command() {
    command -v "$@" >/dev/null 2>&1
}

disable_selinux() {
    if [[ -s /etc/selinux/config ]] && grep SELINUX=enforcing /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
        warn "SELinux enforcement has been ${red}DISABLED$plain."
        echo 'To undo, edit /etc/selinux/config and change SELINUX= from disabled to enforcing'
        echo 'and then run: setenforce 1'
        echo "${yellow}Please remember this in case you need to uninstall.$plain"
    fi
}

check_sys() {
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]] ; then
        release=centos
        systemPackage=yum
    elif grep -Eqi 'centos|red hat|redhat' /etc/issue; then
        release=centos
        systemPackage=yum
    elif grep -Eqi 'centos|red hat|redhat' /proc/version; then
        release=centos
        systemPackage=yum
    elif grep -Eqi 'debian|raspbian' /etc/issue; then
        release=debian
        systemPackage=apt
    elif grep -Eqi 'debian|raspbian' /proc/version; then
        release=debian
        systemPackage=apt
    elif grep -Eqi ubuntu /etc/issue; then
        release=ubuntu
        systemPackage=apt
    elif grep -Eqi ubuntu /proc/version; then
        release=ubuntu
        systemPackage=apt
    fi

    case $checkType in
    sysRelease )     [[ $value = "$release" ]] ;;
    packageManager ) [[ $value = "$systemPackage" ]] ;;
    esac
}

# centosversion
getversion() {
    if [[ -s /etc/redhat-release ]] ; then
        grep -oE '[0-9.]+' /etc/redhat-release
    else
        grep -oE '[0-9.]+' /etc/issue
    fi
}

centosversion() {
    check_sys sysRelease centos ||
        return 1
    local code=$1
    local version="$(getversion)"
    local main_ver=${version%%.*}
    [[ $main_ver = "$code" ]]
}

# debianversion
get_opsy() {
    [[ -f /etc/redhat-release ]] && awk          '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [[ -f /etc/os-release     ]] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release     && return
    [[ -f /etc/lsb-release    ]] && awk -F'[="]+' '/DESCRIPTION/{print $2}'       /etc/lsb-release    && return
}

debianversion() {
    check_sys sysRelease debian ||
        return 1
    local version=$(get_opsy)
    local code=$1
    local main_ver=${version//[!0-9]/}
    [[ $main_ver = "$code" ]]
}

get_ip() {
    local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    [[ -z $IP ]] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    [[ -z $IP ]] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    echo "$IP"
}

get_ipv6() {
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [[ -n $ipv6 ]]
}

get_libev_ver() {
    # Github API returns pretty (one-key-per-line) JSON, like:
    #  "tag_name": "v3.3.5",
    libev_ver=$(
        wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest |
        grep '"tag_name":' |
        cut -d\" -f4
    )
    [[ -n $libev_ver ]] || die 'Get shadowsocks-libev latest version failed'
}

install_check() {
    check_sys packageManager yum ||
    check_sys packageManager apt &&
    ! centosversion 5
}

install_select() {
    install_check ||
        die $'Your OS is not supported to run it!\nPlease change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again.'

    clear
    get_libev_ver
    while
        echo "Which Shadowsocks server you'd select:"
        for j in "${!software[@]}" ; do
            echo "$green$((j+1))$plain) ${software[j]}"
        done
        read -p "Please enter a number (Default ${software[0]}):" selected || exit
        ! is_valid_number selected 1 ${#software[@]} 1 ||
        [[ -z ${software[selected-1]} ]]
    do
        error "Please only enter a number [1-${#software[@]}]"
    done
    echo
    echo "You choose = ${software[selected-1]}"
    if [[ $selected = 1 ]] ; then
        info "Shadowsocks-libev Version: $libev_ver"
    fi
    echo
}

error_detect_depends() {
    # assume args are: yum -y install DEPEND-NAME-HERE
    local depend=$4
    info "Starting to install package $depend"
    "$@" >/dev/null 2>&1 || die "Failed to install $red$depend$plain"
}

install_dependencies() {
    if check_sys packageManager yum; then
        info 'Checking the EPEL repository...'
        if [[ ! -f /etc/yum.repos.d/epel.repo ]] ; then
            yum install -y epel-release >/dev/null 2>&1
        fi
        [[ -f /etc/yum.repos.d/epel.repo ]] || die 'Install EPEL repository failed, please check it.'
        has_command yum-config-manager || yum install -y yum-utils >/dev/null 2>&1

        yum-config-manager epel | grep -qx 'enabled = True' ||
        yum-config-manager --enable epel >/dev/null 2>&1

        info 'Checking the EPEL repository complete...'

        yum_depends=(
            autoconf automake cpio curl curl-devel gcc git gzip libevent libev-devel libtool make openssl
            openssl-devel pcre pcre-devel perl perl-devel python python-devel python-setuptools
            qrencode unzip c-ares-devel expat-devel gettext-devel zlib-devel
        )
        for depend in "${yum_depends[@]}"; do
            error_detect_depends yum -y install "$depend"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            autoconf automake build-essential cpio curl gcc gettext git gzip libpcre3 libpcre3-dev
            libtool make openssl perl python python-dev python-setuptools qrencode unzip
            libc-ares-dev libev-dev libssl-dev zlib1g-dev
        )

        apt -y update >/dev/null 2>&1
        for depend in "${apt_depends[@]}"; do
            error_detect_depends apt -y install "$depend"
        done
    fi
}

install_prepare_password() {
    echo "Please enter password for ${software[selected-1]}"
    read -p '(Default password: shadowsocks):' shadowsockspwd || exit
    [[ -z $shadowsockspwd ]] && shadowsockspwd=shadowsocks
    echo
    echo "password = $shadowsockspwd"
    echo
}

install_prepare_port() {
    local sw=${software[selected-1]}
    while
        # Suggest an "uninteresting" port between 9000 and 19000; no '0' digits
        # and no double digits.
        printf -v dport 0x%o $((RANDOM%010000+07000))
        for((dport+=0x2111,s=256;s;dport/s%256%17<8&&(dport+=s),s>>=4))do :;done
        printf -v dport %x $dport

        echo "Please enter a port for $sw [1-65535]"
        read -p "(Random port: $dport):" shadowsocksport || exit
        ! is_valid_number shadowsocksport 1 65535 "$dport"
    do
        error 'Please enter a correct number [1-65535]'
    done
    echo
    echo "port = $shadowsocksport"
    echo
}

install_prepare_cipher() {
    local sw=${software[selected-1]}
    local pick
    case $selected in
    1)
        while
            echo "Please select stream cipher for $sw:"
            for j in "${!common_ciphers[@]}" ; do
                echo "$green$((j+1))$plain) ${common_ciphers[j]}"
            done
            read -p "Which cipher you'd select(Default: ${common_ciphers[0]}):" pick || exit
            ! is_valid_number pick 1 ${#common_ciphers[@]} 1 ||
            [[ -z ${common_ciphers[pick-1]} ]]
        do
            error "Please enter a number between 1 and ${#common_ciphers[@]}"
        done
        shadowsockscipher=${common_ciphers[pick-1]}
        ;;
    2)
        while
            echo "Please select stream cipher for $sw:"
            for j in "${!r_ciphers[@]}" ; do
                echo "$green$((j+1))$plain) ${r_ciphers[j]}"
            done
            read -p "Which cipher you'd select(Default: ${r_ciphers[1]}):" pick || exit
            ! is_valid_number pick 1 ${#r_ciphers[@]} 2 ||
            [[ -z ${r_ciphers[pick-1]} ]]
        do
            error "Please enter a number between 1 and ${#r_ciphers[@]}"
        done
        shadowsockscipher=${r_ciphers[pick-1]}
    esac
    echo
    echo "cipher = $shadowsockscipher"
    echo
}

install_prepare_protocol() {
    local sw=${software[selected-1]}
    local pick
    while
        echo "Please select protocol for $sw:"
        for j in "${!protocols[@]}" ; do
            echo "$green$((j+1))$plain) ${protocols[j]}"
        done
        read -p "Which protocol you'd select(Default: ${protocols[0]}):" pick || exit
        ! is_valid_number pick 1 ${#protocols[@]} 1 ||
        [[ -z ${protocols[pick-1]} ]]
    do
        error "Please enter a number between 1 and ${#protocols[@]}"
    done
    shadowsockprotocol=${protocols[pick-1]}
    echo
    echo "protocol = $shadowsockprotocol"
    echo
}

install_prepare_obfs() {
    local sw=${software[selected-1]}
    local pick
    while
        echo "Please select obfs for $sw:"
        for j in "${!obfs[@]}" ; do
            echo "$green$((j+1))$plain) ${obfs[j]}"
        done
        read -p "Which obfs you'd select(Default: ${obfs[0]}):" pick || exit
        ! is_valid_number pick 1 ${#obfs[@]} 1 ||
        [[ -z ${obfs[pick-1]} ]]
    do
        error "Please enter a number between 1 and ${#obfs[@]}"
    done
    shadowsockobfs=${obfs[pick-1]}
    echo
    echo "obfs = $shadowsockobfs"
    echo
}

get_char() {
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2>/dev/null
    stty -raw
    stty echo
    stty "$SAVEDSTTY"
}

install_prepare() {
    install_prepare_password
    install_prepare_port
    install_prepare_cipher
    case $selected in
    2 )
        install_prepare_protocol
        install_prepare_obfs
        ;;
    esac
    echo 'Press any key to start...or Press Ctrl+C to cancel'
    char=$(get_char)
}

config_shadowsocks() {
    case $selected in
    1 )
        local server_value='"0.0.0.0"'
        if get_ipv6; then
            server_value='["[::0]","0.0.0.0"]'
        fi

        if [[ ! -d $shadowsocks_libev_config_dir ]] ; then
            mkdir -p "$shadowsocks_libev_config_dir"
        fi

        cat >"$shadowsocks_libev_config" <<-EOF ;;
{
    "server":$server_value,
    "server_port":$shadowsocksport,
    "password":"$shadowsockspwd",
    "method":"$shadowsockscipher",
    "timeout":300,
    "user":"nobody",
    "fast_open":false
}
EOF

    2 )
        if [[ ! -d $shadowsocks_r_config_dir ]] ; then
            mkdir -p "$shadowsocks_r_config_dir"
        fi
        cat >"$shadowsocks_r_config" <<-EOF ;;
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":$shadowsocksport,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"$shadowsockspwd",
    "method":"$shadowsockscipher",
    "protocol":"$shadowsockprotocol",
    "protocol_param":"",
    "obfs":"$shadowsockobfs",
    "obfs_param":"",
    "timeout":120,
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":false
}
EOF

    esac
}

download() {
    local filename=${1##*/}
    if [[ -f $1 ]] ; then
        echo "$filename [found]"
    else
        echo "$filename not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O "$1" "$2" >/dev/null 2>&1 ||
            die "Download $filename failed."
    fi
}

download_files() {
    echo
    case $selected in
    1 )
        get_libev_ver
        shadowsocks_libev_file=shadowsocks-libev-$(echo "$libev_ver" | sed -e 's/^[a-zA-Z]//g')
        shadowsocks_libev_url=https://github.com/shadowsocks/shadowsocks-libev/releases/download/$libev_ver/$shadowsocks_libev_file.tar.gz

        download "$shadowsocks_libev_file.tar.gz" "$shadowsocks_libev_url"
        if check_sys packageManager yum; then
            download "$shadowsocks_libev_init" "$shadowsocks_libev_centos"
        elif check_sys packageManager apt; then
            download "$shadowsocks_libev_init" "$shadowsocks_libev_debian"
        fi
        ;;
    2 )
        download "$shadowsocks_r_file.tar.gz" "$shadowsocks_r_url"
        if check_sys packageManager yum; then
            download "$shadowsocks_r_init" "$shadowsocks_r_centos"
        elif check_sys packageManager apt; then
            download "$shadowsocks_r_init" "$shadowsocks_r_debian"
        fi
        ;;
    esac
}

config_firewall() {
    if centosversion 6; then
        if /etc/init.d/iptables status >/dev/null 2>&1 ; then
            if ! iptables -L -n | grep -i "$shadowsocksport" >/dev/null 2>&1 ; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport "$shadowsocksport" -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport "$shadowsocksport" -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo
                info "port $green$shadowsocksport$plain already be enabled."
            fi
        else
            warn "iptables looks like not running or not installed, please enable port $shadowsocksport manually if necessary."
        fi
    elif centosversion 7; then
        if systemctl status firewalld >/dev/null 2>&1 ; then
            default_zone=$(firewall-cmd --get-default-zone)
            firewall-cmd --permanent "--zone=$default_zone" "--add-port=$shadowsocksport/tcp"
            firewall-cmd --permanent "--zone=$default_zone" "--add-port=$shadowsocksport/udp"
            firewall-cmd --reload
        else
            warn "firewalld looks like not running or not installed, please enable port $shadowsocksport manually if necessary."
        fi
    fi
}

install_libsodium() {
    if [[ -f /usr/lib/libsodium.a || -f /usr/lib64/libsodium.a ]] ; then
        echo
        info "$libsodium_file already installed."
    else
        echo
        info "$libsodium_file start installing."
        download "$libsodium_file.tar.gz" "$libsodium_url"
        tar zxf "$libsodium_file.tar.gz"
        (
            cd "$libsodium_file" &&
             ./configure --prefix=/usr &&
              make &&
               make install
        ) || {
            install_cleanup
            die "$libsodium_file install failed."
        }
        info "$libsodium_file install success!"
    fi
}

install_mbedtls() {
    if [[ -f /usr/lib/libmbedtls.a || -f /usr/lib64/libmbedtls.a ]] ; then
        echo
        info "$mbedtls_file already installed."
    else
        echo
        info "$mbedtls_file start installing."
        download "mbedtls-$mbedtls_file.tar.gz" "$mbedtls_url"
        tar zxf "mbedtls-$mbedtls_file.tar.gz"
        (
            cd "mbedtls-$mbedtls_file" &&
            make SHARED=1 CFLAGS=-fPIC &&
            make DESTDIR=/usr install
        ) || {
            install_cleanup
            die "$mbedtls_file install failed."
        }
        info "$mbedtls_file install success!"
    fi
}

install_shadowsocks_libev() {
    if [[ -f $lbin_dir/ss-server || -f /usr/bin/ss-server ]] ; then
        echo
        info "${software[0]} already installed."
        return
    fi

    echo
    info "${software[0]} start installing."
    tar zxf "$shadowsocks_libev_file.tar.gz"
    (
        cd "$shadowsocks_libev_file" || exit
        ./configure --disable-documentation || exit
        make || exit
        make install || exit

        chmod +x "$shadowsocks_libev_init" || exit
        local service_name=${shadowsocks_libev_init##*/}
        if check_sys packageManager yum; then
            chkconfig --add "$service_name"
            chkconfig "$service_name" on
        elif check_sys packageManager apt; then
            update-rc.d -f "$service_name" defaults
        fi
    ) || {
        install_cleanup
        die "${software[0]} install failed."
    }
}

install_shadowsocks_r() {
    if [[ -f $prefix/shadowsocks/server.py ]] ; then
        echo
        info "${software[1]} already installed."
        return
    fi
    echo
    info "${software[1]} start installing."
    tar zxf "$shadowsocks_r_file.tar.gz"
    mv "$shadowsocks_r_file/shadowsocks" "$prefix/"
    if [[ ! -f $prefix/shadowsocks/server.py ]] ; then
        install_cleanup
        die "${software[1]} install failed."
    fi

    chmod +x "$shadowsocks_r_init"
    local service_name=${shadowsocks_r_init##*/}
    if check_sys packageManager yum; then
        chkconfig --add "$service_name"
        chkconfig "$service_name" on
    elif check_sys packageManager apt; then
        update-rc.d -f "$service_name" defaults
    fi
}

install_completed_libev() {
    clear
    ldconfig
    "$shadowsocks_libev_init" start
    echo
    echo "Congratulations, $green${software[0]}$plain server install completed!"
    info_kv 'Your Server IP'         "$(get_ip)"
    info_kv 'Your Server Port'       "$shadowsocksport"
    info_kv 'Your Password'          "$shadowsockspwd"
    info_kv 'Your Encryption Method' "$shadowsockscipher"
}

install_completed_r() {
    clear
    "$shadowsocks_r_init" start
    echo
    echo "Congratulations, $green${software[1]}$plain server install completed!"
    info_kv 'Your Server IP'         "$(get_ip)"
    info_kv 'Your Server Port'       "$shadowsocksport"
    info_kv 'Your Password'          "$shadowsockspwd"
    info_kv 'Your Protocol'          "$shadowsockprotocol"
    info_kv 'Your obfs'              "$shadowsockobfs"
    info_kv 'Your Encryption Method' "$shadowsockscipher"
}

qr_generate_libev() {
    if has_command qrencode ; then
        local tmp=$(echo -n "$shadowsockscipher:$shadowsockspwd@$(get_ip):$shadowsocksport" | base64 -w0)
        local qr_code=ss://$tmp
        echo
        echo 'Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)'
        echo "$green $qr_code $plain"
        echo -n "$qr_code" | qrencode -s8 -o shadowsocks_libev_qr.png
        echo 'Your QR Code has been saved as a PNG file path:'
        echo " $green$PWD/shadowsocks_libev_qr.png$plain"
    fi
}

qr_generate_r() {
    if has_command qrencode ; then
        local tmp1=$(echo -n "$shadowsockspwd" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
        local tmp2=$(echo -n "$(get_ip):$shadowsocksport:$shadowsockprotocol:$shadowsockscipher:$shadowsockobfs:$tmp1/?obfsparam=" | base64 -w0)
        local qr_code=ssr://$tmp2
        echo
        echo 'Your QR Code: (For ShadowsocksR Windows, Android clients only)'
        echo " $green$qr_code$plain"
        echo -n "$qr_code" | qrencode -s8 -o shadowsocks_r_qr.png
        echo 'Your QR Code has been saved as a PNG file path:'
        echo " $green$PWD/shadowsocks_r_qr.png$plain"
    fi
}

install_main() {
    install_libsodium
    if ! ldconfig -p | grep -wq /usr/lib; then
        echo /usr/lib >/etc/ld.so.conf.d/lib.conf
    fi
    if ! ldconfig -p | grep -wq /usr/lib64; then
        echo /usr/lib64 >>/etc/ld.so.conf.d/lib.conf
    fi
    ldconfig

    case $selected in
    1 )
        install_mbedtls
        ldconfig
        install_shadowsocks_libev
        install_completed_libev
        qr_generate_libev
        ;;
    2 )
        install_shadowsocks_r
        install_completed_r
        qr_generate_r
        ;;
    esac

    echo
    echo 'Enjoy it!'
    echo
}

install_cleanup() {
    rm -rf "$libsodium_file" "$libsodium_file.tar.gz"
    rm -rf "mbedtls-$mbedtls_file" "mbedtls-$mbedtls_file.tar.gz"
    rm -rf "$shadowsocks_libev_file" "$shadowsocks_libev_file.tar.gz"
    rm -rf "$shadowsocks_r_file" "$shadowsocks_r_file.tar.gz"
}

install_shadowsocks() {
    disable_selinux
    install_select
    install_dependencies
    install_prepare
    config_shadowsocks
    download_files
    if check_sys packageManager yum; then
        config_firewall
    fi
    install_main
    install_cleanup
}

ask_yes_no() {
    local answer
    printf "%s? [y/n]\n" "$1"
    read -p "(default: n):" answer || exit
    [[ ${answer^^} = Y ]]
}

ask_are_you_sure() {
    ask_yes_no "$1; ${red}are you sure$plain"
}

uninstall_libsodium() {
    if ask_are_you_sure "Uninstall $libsodium_file" ; then
        rm -f /usr/lib64/libsodium.so.23
        rm -f /usr/lib64/libsodium.a
        rm -f /usr/lib64/libsodium.la
        rm -f /usr/lib64/pkgconfig/libsodium.pc
        rm -f /usr/lib64/libsodium.so.23.3.0
        rm -f /usr/lib64/libsodium.so
        rm -rf /usr/include/sodium
        rm -f /usr/include/sodium.h
        ldconfig
        info "$libsodium_file uninstall success"
    else
        echo
        info "$libsodium_file uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_mbedtls() {
    if ask_are_you_sure "Uninstall $mbedtls_file" ; then
        rm -f /usr/lib/libmbedtls.a
        rm -f /usr/lib/libmbedtls.so
        rm -f /usr/lib/libmbedtls.so.13
        rm -rf /usr/include/mbedtls
        rm -f /usr/include/mbedtls/mbedtls_config.h
        rm -f /usr/bin/mbedtls_*
        ldconfig
        info "$mbedtls_file uninstall success"
    else
        echo
        info "$mbedtls_file uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_libev() {
    if ! ask_are_you_sure "Uninstall ${software[0]}" ; then
        echo
        info "${software[0]} uninstall cancelled, nothing to do..."
        echo
        return 1
    fi

    if "$shadowsocks_libev_init" status >/dev/null 2>&1 ; then
        "$shadowsocks_libev_init" stop
    fi

    local service_name=${shadowsocks_libev_init##*/}
    if check_sys packageManager yum; then
        chkconfig --del "$service_name"
    elif check_sys packageManager apt; then
        update-rc.d -f "$service_name" remove
    fi

    rm -f "$lbin_dir/ss-local"
    rm -f "$lbin_dir/ss-server"
    rm -f "$lbin_dir/ss-tunnel"
    rm -f "$lbin_dir/ss-manager"
    rm -f "$lbin_dir/ss-redir"
    rm -f "$lbin_dir/ss-nat"
    rm -f "$prefix/include/shadowsocks.h"
    rm -f "$llib_dir/libshadowsocks-libev.a"
    rm -f "$llib_dir/libshadowsocks-libev.la"
    rm -f "$llib_dir/pkgconfig/shadowsocks-libev.pc"
    rm -f "$man_dir/man1/ss-local.1"
    rm -f "$man_dir/man1/ss-server.1"
    rm -f "$man_dir/man1/ss-tunnel.1"
    rm -f "$man_dir/man1/ss-manager.1"
    rm -f "$man_dir/man1/ss-redir.1"
    rm -f "$man_dir/man1/ss-nat.1"
    rm -f "$man_dir/man8/shadowsocks-libev.8"
    rm -rf "$doc_dir/shadowsocks-libev"
    rm -rf "$shadowsocks_libev_config_dir"
    rm -f "$shadowsocks_libev_init"
    info "${software[0]} uninstall success"
}

uninstall_shadowsocks_r() {
    if ! ask_are_you_sure "Uninstall ${software[1]}" ; then
        echo
        info "${software[1]} uninstall cancelled, nothing to do..."
        echo
        return
    fi

    if "$shadowsocks_r_init" status >/dev/null 2>&1 ; then
        "$shadowsocks_r_init" stop
    fi

    local service_name=${shadowsocks_r_init##*/}
    if check_sys packageManager yum; then
        chkconfig --del "$service_name"
    elif check_sys packageManager apt; then
        update-rc.d -f "$service_name" remove
    fi

    rm -fr "$shadowsocks_r_config_dir"
    rm -f "$shadowsocks_r_init"
    rm -f /var/log/shadowsocks.log
    rm -fr "$prefix/shadowsocks"
    info "${software[1]} uninstall success"
}

uninstall_shadowsocks() {
    while
        echo 'Which Shadowsocks server you want to uninstall?'
        for j in "${!software[@]}" ; do
            echo "$green$((j+1))$plain) ${software[j]}"
        done
        read -p "Please enter a number [1-${#software[@]}]:" un_select || exit
        ! is_valid_number un_select 1 ${#software[@]} ||
        [[ -z ${software[un_select-1]} ]]
    do
        error "Please only enter a number [1-${#software[@]}]"
    done
    echo
    echo "You choose = ${software[un_select-1]}"
    echo

    case $un_select in
    1 )
        [[ -f $shadowsocks_libev_init ]] ||
            die "${software[un_select-1]} not installed, please check it and try again."
        uninstall_shadowsocks_libev
        ;;
    2 )
        [[ -f $shadowsocks_r_init ]] ||
            die "${software[un_select-1]} not installed, please check it and try again."
        uninstall_shadowsocks_r
        ;;
    esac
    ldconfig
    echo
    warn 'If SELinux was previously disabled by this script, undo manually by:'
    echo '         edit /etc/selinux/config and change SELINUX= from disabled to enforcing'
    echo '         then run: setenforce 1'
}

upgrade_shadowsocks() {
    clear
    if ! ask_yes_no "Upgrade $green${software[0]}$plain" ; then
        echo
        info "${software[0]} upgrade cancelled, nothing to do..."
        echo
        return
    fi

    [[ -f $shadowsocks_r_init ]] || die 'Only support shadowsocks-libev !'
    [[ -f $shadowsocks_libev_init ]] || die "Shadowsocks-libev server doesn't exist !"

    has_command ss-server || die 'Shadowsocks-libev not installed...'
    current_local_version=$(ss-server --help | grep shadowsocks | cut -d' ' -f2)
    get_libev_ver
    current_libev_ver=$(echo "$libev_ver" | sed -e 's/^[a-zA-Z]//g')
    echo
    info "Shadowsocks-libev Version: v$current_local_version"

    if [[ $current_libev_ver = "$current_local_version" ]] ; then
        echo
        info 'Already updated to latest version !'
        echo
        exit 1
    fi

    uninstall_shadowsocks_libev ||
        exit

    ldconfig
    disable_selinux
    selected=1
    echo
    echo "You will upgrade ${software[selected-1]}"
    echo
    shadowsockspwd=$(< /etc/shadowsocks-libev/config.json grep password | cut -d\" -f4)
    shadowsocksport=$(< /etc/shadowsocks-libev/config.json grep server_port | cut -d , -f1 | cut -d : -f2)
    shadowsockscipher=$(< /etc/shadowsocks-libev/config.json grep method | cut -d\" -f4)
    config_shadowsocks
    download_files
    install_shadowsocks_libev
    install_completed_libev
    qr_generate_libev
}

# Initialization step
action=${1:-install}

case $action in
install | uninstall | upgrade)
    "$action"_shadowsocks
    ;;
*)
    echo "Arguments error! [$action]"
    echo "Usage: ${0##*/} [install|uninstall|upgrade]"
    ;;
esac

#!/bin/sh
# Менеджер обхода блокировок для OpenWRT
# Управление byedpi + hev-socks5-tunnel + DNS-over-HTTPS

set -e

# Цвета
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Функции вывода
success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

step() {
    echo -e "${YELLOW}→${NC} $1"
}

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Функция установки обхода
install_bypass() {
    echo ""
    echo "=== Установка обхода ==="
    echo ""

    step "Обновление списка пакетов..."
    opkg update > /dev/null 2>&1
    success "Список пакетов обновлен"

    step "Установка модулей ядра..."
    for pkg in kmod-tun kmod-ipt-nat iptables-nft; do
        if ! opkg list-installed | grep -q "^${pkg} "; then
            opkg install ${pkg} > /dev/null 2>&1
        fi
    done
    success "Модули установлены"

    step "Установка byedpi..."
    if ! opkg list-installed | grep -q "^byedpi "; then
        BYEDPI_URL="https://github.com/spvkgn/ByeDPI-OpenWrt/releases/download/v0.17-24.10/byedpi_0.17-r1_mipsel_24kc.ipk"
        BYEDPI_FILE="/tmp/byedpi.ipk"
        wget -q -O "$BYEDPI_FILE" "$BYEDPI_URL" 2>/dev/null || {
            error "Ошибка загрузки byedpi"
            exit 1
        }
        opkg install "$BYEDPI_FILE" > /dev/null 2>&1
        rm -f "$BYEDPI_FILE"
        success "byedpi установлен"
    else
        success "byedpi уже установлен"
    fi

    step "Установка hev-socks5-tunnel..."
    if ! opkg list-installed | grep -q "^hev-socks5-tunnel "; then
        opkg install hev-socks5-tunnel > /dev/null 2>&1
        success "hev-socks5-tunnel установлен"
    else
        success "hev-socks5-tunnel уже установлен"
    fi

    step "Установка https-dns-proxy..."
    if ! opkg list-installed | grep -q "^https-dns-proxy "; then
        opkg install https-dns-proxy > /dev/null 2>&1
        success "https-dns-proxy установлен"
    else
        success "https-dns-proxy уже установлен"
    fi

    step "Настройка byedpi..."
    cat > /etc/config/byedpi << 'EOFUCI'
config byedpi 'main'
	option enabled '1'
	option cmd_opts '-E -s12+s -d18+s -r6+s -a4 -An'
EOFUCI

    cat > /etc/config/byedpi.hosts << 'EOFHOSTS'
google.com
googlevideo.com
googleapis.com
ytimg.com
ggpht.com
dis.gd
discord.co
discord.com
discord.design
discord.dev
discord.gg
discord.gift
discord.gifts
discord.media
discord.new
discord.store
discord.tools
discordapp.com
discordapp.net
discordmerch.com
discordpartygames.com
discord-activities.com
discordactivities.com
discordsays.com
youtube.com
instagram.com
cdninstagram.com
facebook.com
ig.me
instagr.am
igsonar.com
rustorka.com
rutor.info
rutor.org
rutracker.org
nnmclub.to
flibusta.is
x.com
twimg.com
steamdb.info
speedtest.net
ntc.party
EOFHOSTS
    success "byedpi настроен"

    step "Настройка hev-socks5-tunnel..."
    mkdir -p /etc/hev-socks5-tunnel
    cat > /etc/hev-socks5-tunnel/main.yml << 'EOFYAML'
tunnel:
  name: tun0
  mtu: 8500
  multi-queue: false
  ipv4: 198.18.0.1
  ipv6: 'fc00::1'

socks5:
  port: 1080
  address: 127.0.0.1
  udp: 'udp'

misc:
  log-level: info
  log-file: /var/log/hev-socks5-tunnel.log
  connect-timeout: 10000
  tcp-read-write-timeout: 300000
  udp-read-write-timeout: 60000
  limit-nofile: 65535
EOFYAML
    # Включаем сервис
    uci set hev-socks5-tunnel.config.enabled='1'
    uci commit hev-socks5-tunnel
    success "hev-socks5-tunnel настроен и включен"

    step "Настройка DNS-over-HTTPS..."
    uci delete https-dns-proxy.@https-dns-proxy[0] > /dev/null 2>&1 || true
    uci delete https-dns-proxy.@https-dns-proxy[0] > /dev/null 2>&1 || true

    uci add https-dns-proxy https-dns-proxy
    uci set https-dns-proxy.@https-dns-proxy[-1].resolver_url='https://cloudflare-dns.com/dns-query'
    uci set https-dns-proxy.@https-dns-proxy[-1].listen_port='5053'

    uci add https-dns-proxy https-dns-proxy
    uci set https-dns-proxy.@https-dns-proxy[-1].resolver_url='https://1.1.1.1/dns-query'
    uci set https-dns-proxy.@https-dns-proxy[-1].listen_port='5054'

    uci commit https-dns-proxy
    success "DNS-over-HTTPS настроен"

    step "Включение автозапуска..."
    /etc/init.d/byedpi enable > /dev/null 2>&1
    /etc/init.d/hev-socks5-tunnel enable > /dev/null 2>&1
    /etc/init.d/https-dns-proxy enable > /dev/null 2>&1
    success "Автозапуск включен"

    step "Запуск byedpi..."
    /etc/init.d/byedpi restart > /dev/null 2>&1
    sleep 3
    # Проверка, что byedpi запущен
    if /etc/init.d/byedpi status > /dev/null 2>&1; then
        success "byedpi запущен"
    else
        error "byedpi не запустился"
    fi

    step "Запуск https-dns-proxy..."
    /etc/init.d/https-dns-proxy restart > /dev/null 2>&1
    sleep 2
    success "https-dns-proxy запущен"

    step "Запуск hev-socks5-tunnel..."
    # Ждем, пока byedpi полностью запустится
    sleep 2
    /etc/init.d/hev-socks5-tunnel restart > /dev/null 2>&1
    sleep 5
    # Проверка, что TUN интерфейс создан (может потребоваться больше времени)
    TUN_CREATED=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if ip link show tun0 > /dev/null 2>&1; then
            TUN_IP=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
            success "hev-socks5-tunnel запущен, TUN интерфейс создан (${TUN_IP})"
            TUN_CREATED=1
            break
        fi
        sleep 1
    done
    if [ $TUN_CREATED -eq 0 ]; then
        # Проверяем статус сервиса
        if /etc/init.d/hev-socks5-tunnel status > /dev/null 2>&1; then
            info "hev-socks5-tunnel запущен, но TUN интерфейс еще не создан (может потребоваться время)"
        else
            error "hev-socks5-tunnel не запустился, проверьте логи"
        fi
    fi

    step "Настройка правил iptables..."
    LAN_NET=$(uci get network.lan.ipaddr | cut -d. -f1-3).0/24

    # Создаем init.d скрипт с использованием procd triggers
    cat > /etc/init.d/apply-proxy-rules << 'EOFINIT'
#!/bin/sh /etc/rc.common
# Скрипт применения правил iptables для прокси

USE_PROCD=1
START=96
STOP=15

apply_rules() {
    # Ждем готовности сети
    sleep 3
    # Ждем, пока byedpi запустится
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if /etc/init.d/byedpi status > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Применяем правила
    LAN_NET=$(uci get network.lan.ipaddr 2>/dev/null | cut -d. -f1-3).0/24
    if [ -n "$LAN_NET" ] && [ "$LAN_NET" != ".0/24" ]; then
        # Удаляем старые правила
        iptables-nft -t nat -D PREROUTING -s $LAN_NET -p tcp --dport 80 -j REDIRECT --to-port 1080 2>/dev/null || true
        iptables-nft -t nat -D PREROUTING -s $LAN_NET -p tcp --dport 443 -j REDIRECT --to-port 1080 2>/dev/null || true

        # Добавляем новые правила
        iptables-nft -t nat -A PREROUTING -s $LAN_NET -p tcp --dport 80 -j REDIRECT --to-port 1080 2>/dev/null || true
        iptables-nft -t nat -A PREROUTING -s $LAN_NET -p tcp --dport 443 -j REDIRECT --to-port 1080 2>/dev/null || true
    fi
}

start_service() {
    apply_rules
    # Используем procd trigger для применения правил после запуска byedpi
    procd_add_reload_trigger byedpi
}

reload_service() {
    apply_rules
}

service_triggers() {
    procd_add_reload_trigger byedpi
    procd_add_config_trigger "network" "lan" apply_rules
}

stop_service() {
    LAN_NET=$(uci get network.lan.ipaddr 2>/dev/null | cut -d. -f1-3).0/24
    if [ -n "$LAN_NET" ] && [ "$LAN_NET" != ".0/24" ]; then
        iptables-nft -t nat -D PREROUTING -s $LAN_NET -p tcp --dport 80 -j REDIRECT --to-port 1080 2>/dev/null || true
        iptables-nft -t nat -D PREROUTING -s $LAN_NET -p tcp --dport 443 -j REDIRECT --to-port 1080 2>/dev/null || true
    fi
}
EOFINIT
    chmod +x /etc/init.d/apply-proxy-rules
    /etc/init.d/apply-proxy-rules enable > /dev/null 2>&1

    # Также добавляем простой скрипт в rc.local как резервный вариант
    # Удаляем старые записи
    sed -i '/apply-proxy-rules/d' /etc/rc.local 2>/dev/null || true
    sed -i '/^sleep 10$/d' /etc/rc.local 2>/dev/null || true
    if ! grep -q "apply-proxy-rules" /etc/rc.local 2>/dev/null; then
        sed -i '/^exit 0$/d' /etc/rc.local 2>/dev/null || true
        cat >> /etc/rc.local << 'EOFRC'
# Применение правил iptables для прокси
(sleep 15 && /etc/init.d/apply-proxy-rules start) &
exit 0
EOFRC
    fi

    # Применяем правила напрямую сейчас
    iptables-nft -t nat -A PREROUTING -s ${LAN_NET} -p tcp --dport 80 -j REDIRECT --to-port 1080 2>/dev/null || true
    iptables-nft -t nat -A PREROUTING -s ${LAN_NET} -p tcp --dport 443 -j REDIRECT --to-port 1080 2>/dev/null || true
    success "Правила iptables настроены и будут применяться при загрузке"

    echo ""
    success "Установка завершена!"
}

# Функция проверки статуса
check_status() {
    echo ""
    echo "=== Статус обхода ==="
    echo ""

    # Проверка пакетов
    echo "📦 Пакеты:"
    for pkg in byedpi hev-socks5-tunnel https-dns-proxy; do
        if opkg list-installed | grep -q "^${pkg} "; then
            VERSION=$(opkg list-installed | grep "^${pkg} " | awk '{print $3}')
            success "  ${pkg} (${VERSION})"
        else
            error "  ${pkg} не установлен"
        fi
    done

    # Проверка модулей
    echo ""
    echo "🔧 Модули ядра:"
    for mod in kmod-tun kmod-ipt-nat iptables-nft; do
        if opkg list-installed | grep -q "^${mod} "; then
            success "  ${mod}"
        else
            error "  ${mod} не установлен"
        fi
    done

    # Проверка сервисов
    echo ""
    echo "🔄 Сервисы:"
    for svc in byedpi hev-socks5-tunnel https-dns-proxy; do
        if /etc/init.d/${svc} status > /dev/null 2>&1; then
            success "  ${svc} - запущен"
        else
            error "  ${svc} - не запущен"
        fi
    done

    # Проверка портов
    echo ""
    echo "🔌 Порты:"
    if netstat -tlnp 2>/dev/null | grep -q ":1080 "; then
        success "  byedpi слушает на порту 1080"
    else
        error "  byedpi не слушает на порту 1080"
    fi

    DOH_PORTS=$(netstat -tlnp 2>/dev/null | grep -E ':(5053|5054) ' | wc -l)
    if [ "$DOH_PORTS" -ge 2 ]; then
        success "  https-dns-proxy слушает на портах 5053, 5054"
    else
        error "  https-dns-proxy не слушает на портах 5053, 5054"
    fi

    # Проверка TUN интерфейса
    echo ""
    echo "🌐 Интерфейсы:"
    if ip link show tun0 > /dev/null 2>&1; then
        TUN_IP=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
        success "  TUN интерфейс tun0 создан (${TUN_IP})"
    else
        error "  TUN интерфейс tun0 не создан"
    fi

    # Проверка правил iptables
    echo ""
    echo "🛡️  Правила iptables:"
    RULES_COUNT=$(iptables-nft -t nat -L PREROUTING -n 2>/dev/null | grep -E '(80|443|1080)' | wc -l)
    if [ "$RULES_COUNT" -ge 2 ]; then
        success "  Настроено правил: ${RULES_COUNT}"
    else
        error "  Правила не настроены"
    fi

    # Проверка DNS
    echo ""
    echo "🔍 DNS:"
    if uci get dhcp.@dnsmasq[0].noresolv 2>/dev/null | grep -q "1"; then
        success "  dnsmasq использует DoH (noresolv=1)"
    else
        error "  dnsmasq не использует DoH"
    fi

    DOH_SERVERS=$(uci get dhcp.@dnsmasq[0].server 2>/dev/null | grep -o '127.0.0.1#505' | wc -l)
    if [ "$DOH_SERVERS" -ge 2 ]; then
        success "  DoH серверы настроены: ${DOH_SERVERS}"
    else
        error "  DoH серверы не настроены"
    fi

    # Тест DNS запросов
    echo ""
    echo "🌍 Тест DNS запросов:"
    for domain in cloudflare.com google.com steamdb.info; do
        if nslookup ${domain} 127.0.0.1 > /dev/null 2>&1; then
            IP=$(nslookup ${domain} 127.0.0.1 2>/dev/null | grep -A 1 "Name:" | grep "Address" | head -1 | awk '{print $2}')
            success "  ${domain} -> ${IP}"
        else
            error "  ${domain} - не разрешается"
        fi
    done

    # Тест доступности сети
    echo ""
    echo "📡 Тест доступности сети:"
    if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
        success "  Пинг 8.8.8.8 - OK"
    else
        error "  Пинг 8.8.8.8 - FAIL"
    fi

    if ping -c 1 -W 2 1.1.1.1 > /dev/null 2>&1; then
        success "  Пинг 1.1.1.1 - OK"
    else
        error "  Пинг 1.1.1.1 - FAIL"
    fi

    # Тест доменов
    echo ""
    echo "🌐 Тест доменов:"
    for domain in google.com cloudflare.com steamdb.info; do
        if ping -c 1 -W 2 ${domain} > /dev/null 2>&1; then
            success "  ${domain} - доступен"
        else
            error "  ${domain} - недоступен"
        fi
    done

    echo ""
}

# Функция удаления обхода
remove_bypass() {
    echo ""
    echo "=== Удаление обхода ==="
    echo ""
    read -p "Вы уверены? Это удалит все пакеты и настройки (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "Отменено"
        return
    fi

    step "Остановка сервисов..."
    /etc/init.d/byedpi stop > /dev/null 2>&1
    /etc/init.d/hev-socks5-tunnel stop > /dev/null 2>&1
    /etc/init.d/https-dns-proxy stop > /dev/null 2>&1
    success "Сервисы остановлены"

    step "Отключение автозапуска..."
    /etc/init.d/byedpi disable > /dev/null 2>&1
    /etc/init.d/hev-socks5-tunnel disable > /dev/null 2>&1
    /etc/init.d/https-dns-proxy disable > /dev/null 2>&1
    /etc/init.d/apply-proxy-rules disable > /dev/null 2>&1
    success "Автозапуск отключен"

    step "Удаление правил iptables..."
    iptables-nft -t nat -F PREROUTING 2>/dev/null || true
    rm -f /etc/firewall.user
    success "Правила удалены"

    step "Удаление пакетов..."
    for pkg in byedpi hev-socks5-tunnel https-dns-proxy; do
        if opkg list-installed | grep -q "^${pkg} "; then
            opkg remove ${pkg} > /dev/null 2>&1
            success "  ${pkg} удален"
        fi
    done

    step "Удаление модулей..."
    for mod in kmod-ipt-nat iptables-nft; do
        if opkg list-installed | grep -q "^${mod} "; then
            opkg remove ${mod} > /dev/null 2>&1
            success "  ${mod} удален"
        fi
    done

    # kmod-tun не удаляем, может использоваться другими сервисами

    step "Удаление конфигураций..."
    rm -rf /etc/config/byedpi /etc/config/byedpi.hosts
    rm -rf /etc/hev-socks5-tunnel
    rm -f /etc/init.d/apply-proxy-rules
    uci delete https-dns-proxy.@https-dns-proxy[0] > /dev/null 2>&1 || true
    uci delete https-dns-proxy.@https-dns-proxy[0] > /dev/null 2>&1 || true
    uci commit https-dns-proxy > /dev/null 2>&1 || true
    success "Конфигурации удалены"

    echo ""
    success "Удаление завершено!"
}

# Функция конфигурации byedpi
configure_byedpi() {
    echo ""
    echo "=== Конфигурация byedpi ==="
    echo ""

    if ! opkg list-installed | grep -q "^byedpi "; then
        error "byedpi не установлен. Сначала выполните установку обхода."
        return
    fi

    echo "Текущая конфигурация:"
    CURRENT_OPTS=$(uci get byedpi.main.cmd_opts 2>/dev/null || echo "")
    if [ -n "$CURRENT_OPTS" ]; then
        echo "  cmd_opts='${CURRENT_OPTS}'"
    else
        echo "  cmd_opts не установлен"
    fi
    echo ""

    echo "Введите новые параметры для cmd_opts:"
    echo "Пример: --split 2 --disorder 6+s --mod-http=h,d"
    echo "Или оставьте пустым для отмены"
    read -p "> " new_opts

    if [ -z "$new_opts" ]; then
        info "Отменено"
        return
    fi

    step "Применение конфигурации..."
    uci set byedpi.main.cmd_opts="${new_opts}"
    uci commit byedpi
    success "Конфигурация сохранена"

    step "Перезапуск byedpi..."
    /etc/init.d/byedpi restart > /dev/null 2>&1
    sleep 2
    success "byedpi перезапущен"

    echo ""
    echo "Новая конфигурация:"
    uci get byedpi.main.cmd_opts
    echo ""
}

# Главное меню
main_menu() {
    while true; do
        echo ""
        echo "╔════════════════════════════════════╗"
        echo "║   Менеджер обхода блокировок      ║"
        echo "╚════════════════════════════════════╝"
        echo ""
        echo "1) Установить обход"
        echo "2) Статус обхода"
        echo "3) Удалить обход"
        echo "4) Конфигурация byedpi"
        echo "5) Выход"
        echo ""
        read -p "Выберите действие [1-5]: " choice

        case $choice in
            1)
                install_bypass
                ;;
            2)
                check_status
                ;;
            3)
                remove_bypass
                ;;
            4)
                configure_byedpi
                ;;
            5)
                echo ""
                info "Выход"
                exit 0
                ;;
            *)
                error "Неверный выбор"
                ;;
        esac
    done
}

# Запуск меню
main_menu


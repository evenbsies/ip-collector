"""全自动住宅 SOCKS5 池：抓 App 同款公益源 -> SOCKS5 拨测 -> ip-api ASN 验真 -> 输出面板链式行.

数据流（与 CFProbe App 的 9 个住宅源同源，全部在 Runner 里自动跑）：
  抓取：Geonode API（ISP 预筛，只留家宽运营商）+ ProxyScrape v4 API + GitHub 4 个 socks5 清单
  拨测：对每个候选做 SOCKS5 CONNECT 到 ip-api.com:80，走代理发一次 /json/ 请求，
        一次请求同时拿到出口 IP、国家、ISP、hosting 标志（请求从各出口 IP 发出，
        不触发 ip-api 单 IP 限速；45 次/分钟是按源 IP 计的）
  验真：hosting=false 且 ISP/ORG/AS 不含机房关键词才算住宅
  输出：residential_socks.txt，每行一条面板链式行，可直接加进 edgetunnel 自定义优选
        格式：cdn.204910.best:443#美国-住宅-S01$socks5://IP:port

安全熔断：本次验真 < 3 个时不覆盖旧文件（防接口抖动把池子清空）。
"""
import json
import re
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
# 与 filter.py 同一套目标国家（欧美 + 亚洲）
EU_US_COUNTRIES = {'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'SE', 'PL', 'CH'}
ASIA_COUNTRIES = {'JP', 'KR', 'TW', 'HK', 'SG', 'MY', 'TH', 'VN', 'PH', 'ID', 'IN'}
ALL_TARGETS = EU_US_COUNTRIES | ASIA_COUNTRIES

# 与 CFProbe App 的 RES_ISP_KEYS 同一套家宽运营商名（Geonode 预筛用）
RES_ISP_KEYS = ["Comcast", "Cox", "Charter", "Spectrum", "Verizon", "AT&T", "Frontier",
    "CenturyLink", "SoftBank", "KDDI", "NTT", "So-net", "Virgin", "Orange", "Deutsche Telekom",
    "Vodafone", "BT ", "Sky", "TalkTalk", "Optus", "Telstra", "Rogers", "Bell", "Shaw",
    "Korea Telecom", "SK Broadband", "LG U", "China Telecom", "China Unicom", "China Mobile",
    "Jio", "Airtel", "Claro", "Telefonica", "Oi ", "TIM "]

BLOCKED_KEYWORDS = [
    'hosting', 'datacenter', 'cloud', 'server', 'digitalocean',
    'linode', 'vultr', 'amazon', 'aws', 'google', 'microsoft',
    'alibaba', 'tencent', 'oracle', 'ovh'
]

# 国家代码 -> 面板节点名
CC_ZH = {'US': '美国', 'CA': '加拿大', 'GB': '英国', 'DE': '德国', 'FR': '法国',
    'NL': '荷兰', 'IT': '意大利', 'ES': '西班牙', 'SE': '瑞典', 'PL': '波兰',
    'CH': '瑞士', 'JP': '日本', 'KR': '韩国', 'TW': '台湾', 'HK': '香港',
    'SG': '新加坡', 'MY': '马来西亚', 'TH': '泰国', 'VN': '越南', 'PH': '菲律宾',
    'ID': '印尼', 'IN': '印度'}

ENTRY_HOST = "cdn.204910.best:443"   # 链式行入口，与面板现有两条链式行一致
MAX_PER_COUNTRY = 8                  # 每国最多 8 条
MAX_TOTAL = 40                       # 总共最多 40 条
FUSE_MIN = 3                         # 熔断：验真少于 3 条不覆盖旧文件

OUTPUT_FILE = "residential_socks.txt"
IP_PORT_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}')
# ==========================================


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='ignore')


def fetch_geonode():
    """Geonode API：500 条 socks5，按 ISP 名预筛家宽（与 App 的 Geonode 住宅池同款）"""
    out = {}
    try:
        data = json.loads(http_get(
            "https://proxylist.geonode.com/api/proxy-list"
            "?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"))
        for o in data.get('data', []):
            isp = o.get('isp', '') or ''
            if not any(k in isp for k in RES_ISP_KEYS):
                continue
            ip, port = o.get('ip', ''), o.get('port', '')
            if ip and port:
                out[f"{ip}:{port}"] = (ip, int(port))
        print(f"[Geonode住宅] 预筛后 {len(out)} 条")
    except Exception as e:
        print(f"[Geonode住宅] 抓取失败: {e}")
    return out


def fetch_proxyscrape():
    """ProxyScrape v4 免费 API：socks5 文本清单（量大，只取前 500 行）"""
    out = {}
    try:
        txt = http_get(
            "https://api.proxyscrape.com/v4/free-proxy-list/get"
            "?request=display_proxies&proxy_format=protocolipport&format=text"
            "&protocol=socks5&timeout=3000")
        for line in txt.splitlines()[:500]:
            m = IP_PORT_RE.search(line.strip())
            if m:
                ip, port = m.group(0).split(':')
                out[m.group(0)] = (ip, int(port))
        print(f"[ProxyScrape] {len(out)} 条")
    except Exception as e:
        print(f"[ProxyScrape] 抓取失败: {e}")
    return out


GITHUB_POOLS = {
    "TheSpeedX": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "monosans": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "ShiftyTR": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "roosterkid": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
}


def fetch_github_pool(name, url):
    out = {}
    try:
        txt = http_get(url)
        for line in txt.splitlines()[:300]:
            m = IP_PORT_RE.search(line.strip())
            if m:
                ip, port = m.group(0).split(':')
                out[m.group(0)] = (ip, int(port))
        print(f"[GitHub池-{name}] {len(out)} 条")
    except Exception as e:
        print(f"[GitHub池-{name}] 抓取失败: {e}")
    return out


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("连接提前关闭")
        buf += chunk
    return buf


def socks5_tunnel(proxy_ip, proxy_port, target_host, target_port, timeout=10):
    """纯标准库 SOCKS5 无认证 CONNECT，返回已接通目标的 socket（失败抛异常）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_ip, proxy_port))
    try:
        s.sendall(b'\x05\x01\x00')                       # VER=5, 1 种方法：无认证
        r = recv_exact(s, 2)
        if r[0] != 5 or r[1] != 0:
            raise IOError("代理拒绝无认证")
        host_b = target_host.encode()
        s.sendall(b'\x05\x01\x00\x03' + bytes([len(host_b)]) + host_b
                  + struct.pack('>H', target_port))      # CONNECT + 域名型地址
        r = recv_exact(s, 4)
        if r[0] != 5 or r[1] != 0:
            raise IOError(f"CONNECT 被拒 rep={r[1]}")
        atyp = r[3]
        if atyp == 1:
            recv_exact(s, 6)                             # IPv4 + 端口
        elif atyp == 3:
            ln = recv_exact(s, 1)[0]
            recv_exact(s, ln + 2)                        # 域名 + 端口
        elif atyp == 4:
            recv_exact(s, 18)                            # IPv6 + 端口
        else:
            raise IOError(f"未知 ATYP={atyp}")
        return s
    except Exception:
        s.close()
        raise


def verify_one(item):
    """拨测一条：走代理查 ip-api，返回 (key, info)；失败返回 (key, None)。
    info 含出口 IP、国家、ISP、hosting、延迟。"""
    key, (ip, port) = item
    start = time.time()
    try:
        s = socks5_tunnel(ip, port, "ip-api.com", 80, timeout=10)
        try:
            s.settimeout(10)
            s.sendall(b"GET /json/?fields=status,country,countryCode,isp,org,as,hosting,proxy,query"
                      b" HTTP/1.0\r\nHost: ip-api.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            raw = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 65536:
                    break
        finally:
            s.close()
        body = raw.split(b'\r\n\r\n', 1)[1]
        d = json.loads(body.decode('utf-8', errors='ignore'))
        if d.get('status') != 'success':
            return (key, None)
        latency = int((time.time() - start) * 1000)
        return (key, {
            'ip': ip, 'port': port, 'exit_ip': d.get('query', ''),
            'country': (d.get('countryCode') or '').upper(),
            'isp': d.get('isp', '') or '',
            'org': d.get('org', '') or '',
            'as': d.get('as', '') or '',
            'hosting': bool(d.get('hosting', True)),
            'latency': latency,
        })
    except Exception:
        return (key, None)


def is_residential(info):
    """验真：非 hosting，且 ISP/ORG/AS 不含机房关键词，且国家在目标列表"""
    if info['hosting']:
        return False
    if info['country'] not in ALL_TARGETS:
        return False
    org_full = f"{info['isp']} {info['org']} {info['as']}".lower()
    if any(kw in org_full for kw in BLOCKED_KEYWORDS):
        return False
    return True


def main():
    print("=== 全自动住宅 SOCKS5 池：抓取 -> 拨测 -> ASN 验真 ===")
    cands = {}
    cands.update(fetch_geonode())
    cands.update(fetch_proxyscrape())
    for name, url in GITHUB_POOLS.items():
        cands.update(fetch_github_pool(name, url))
    if len(cands) > 1200:
        cands = dict(list(cands.items())[:1200])
    print(f"聚合候选: {len(cands)} 个")

    verified = []
    with ThreadPoolExecutor(max_workers=40) as pool:
        for key, info in pool.map(verify_one, list(cands.items())):
            if info and is_residential(info):
                verified.append(info)
                print(f"  [+] 住宅: {info['country']} | {info['ip']}:{info['port']} "
                      f"(出口 {info['exit_ip']}, {info['latency']}ms) - {info['isp']}")

    print(f"验真通过: {len(verified)} 个")
    if len(verified) < FUSE_MIN:
        print(f"【安全熔断】验真少于 {FUSE_MIN} 个，疑似接口抖动！放弃写入，保留旧文件。")
        return

    verified.sort(key=lambda x: x['latency'])
    per_country = {}
    lines = []
    for info in verified:
        cc = info['country']
        n = per_country.get(cc, 0)
        if n >= MAX_PER_COUNTRY or len(lines) >= MAX_TOTAL:
            continue
        per_country[cc] = n + 1
        zh = CC_ZH.get(cc, cc)
        name = f"{zh}-住宅-S{per_country[cc]:02d}"
        lines.append(f"{ENTRY_HOST}#{name}$socks5://{info['ip']}:{info['port']}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"写入 {OUTPUT_FILE}: {len(lines)} 行")


if __name__ == "__main__":
    main()

import base64
import csv
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
# 目标国家代码（优先筛选家宽资源集中地）
TARGET_COUNTRIES = {'JP', 'KR', 'TW', 'SG', 'US', 'CA', 'AU'}

# 严格过滤已知机房/托管服务商特征
BLOCKED_KEYWORDS = [
    'hosting', 'datacenter', 'cloud', 'server', 'digitalocean', 
    'linode', 'vultr', 'amazon', 'aws', 'google', 'microsoft', 
    'alibaba', 'tencent', 'oracle', 'ovh', 'public-vpn', 'vpngate'
]
BLOCKED_SUBNETS = ['219.100.37.']  # VPNGate 官方机房段
MAX_FINAL_NODES = 20               # 最终保留的高质量节点数
# ==========================================


# ---------------- 1. 数据采集模块 ----------------
def fetch_source_vpngate():
    """源一：VPNGate 公益家宽接口 (OpenVPN TCP)"""
    url = "https://www.vpngate.net/api/iphone/"
    candidates = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = [l.decode('utf-8', errors='ignore').strip() for l in resp.readlines()]
            if len(lines) > 2:
                reader = csv.reader(lines[1:])
                for row in reader:
                    if len(row) < 15: continue
                    host_name, ip, country, config_b64 = row[0], row[1], row[6].upper(), row[-1]
                    if country not in TARGET_COUNTRIES or any(ip.startswith(s) for s in BLOCKED_SUBNETS):
                        continue
                    if any(kw in host_name.lower() for kw in BLOCKED_KEYWORDS):
                        continue
                    
                    # 解包检查是否为 TCP 协议
                    try:
                        cfg = base64.b64decode(config_b64).decode('utf-8', errors='ignore')
                        proto = re.search(r'^\s*proto\s+(tcp|udp)', cfg, re.M | re.I)
                        if not proto or proto.group(1).lower() != 'tcp': continue
                        port_m = re.search(r'^\s*remote\s+[\d\.]+\s+(\d+)', cfg, re.M | re.I)
                        port = port_m.group(1) if port_m else "443"
                        candidates.append({
                            'ip': ip, 'port': int(port), 'country': country, 
                            'type': 'openvpn', 'config_b64': config_b64
                        })
                    except Exception:
                        continue
    except Exception as e:
        print(f"[源1 - VPNGate] 获取失败: {e}")
    print(f"[源1 - VPNGate] 提取候选: {len(candidates)} 个")
    return candidates

def fetch_source_geonode():
    """源二：Geonode API 实时代理库 (SOCKS5/SOCKS4/HTTP)"""
    url = "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc"
    candidates = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get('data', []):
                ip = item.get('ip')
                port = item.get('port')
                country = (item.get('country') or '').upper()
                protocols = item.get('protocols', [])
                
                # 优先提取 SOCKS5 代理
                proto_type = 'socks5' if 'socks5' in protocols else ('http' if 'http' in protocols else None)
                if not proto_type: continue
                if country in TARGET_COUNTRIES and ip and port:
                    candidates.append({
                        'ip': ip, 'port': int(port), 'country': country, 
                        'type': proto_type, 'config_b64': None
                    })
    except Exception as e:
        print(f"[源2 - Geonode] 获取失败: {e}")
    print(f"[源2 - Geonode] 提取候选: {len(candidates)} 个")
    return candidates

def fetch_source_github_socks5():
    """源三：GitHub 高频维护的公共 SOCKS5 代理源"""
    urls = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
    ]
    candidates = []
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
                for line in text.splitlines():
                    match = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', line.strip())
                    if match:
                        candidates.append({
                            'ip': match.group(1), 'port': int(match.group(2)), 
                            'country': 'UNKNOWN', 'type': 'socks5', 'config_b64': None
                        })
        except Exception:
            continue
    # 取前 150 个待测候选
    selected = candidates[:150]
    print(f"[源3 - GitHub SOCKS5] 提取候选: {len(selected)} 个")
    return selected


# ---------------- 2. 并发连通性测试 ----------------
def check_port(node, timeout=2.0):
    """TCP 握手探针：过滤假死和无响应 IP"""
    ip, port = node['ip'], node['port']
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = (sock.connect_ex((ip, port)) == 0)
        sock.close()
        return node if ok else None
    except:
        return None

def filter_alive_nodes(nodes):
    print(f"正在进行 TCP 端口并发测活 ({len(nodes)} 个候选)...")
    alive = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        results = pool.map(check_port, nodes)
        for r in results:
            if r: alive.append(r)
    print(f"TCP 连通成功: {len(alive)} 个")
    return alive


# ---------------- 3. 批量纯净度与 ISP 校验 ----------------
def batch_validate_residential(alive_nodes):
    """使用 ip-api.com/batch 单次校验最多 100 个 IP 的 ISP/Hosting 属性"""
    if not alive_nodes: return []
    
    # 提取待查 IP 并去重
    ip_map = {}
    for node in alive_nodes:
        ip_map[node['ip']] = node
        
    unique_ips = list(ip_map.keys())[:100] # 单批上限 100
    post_payload = json.dumps([
        {"query": ip, "fields": "status,countryCode,isp,org,as,hosting,query"} 
        for ip in unique_ips
    ]).encode('utf-8')

    req = urllib.request.Request(
        "http://ip-api.com/batch", 
        data=post_payload, 
        headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    )

    clean_residential_nodes = []
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for item in data:
                if item.get('status') != 'success': continue
                
                is_hosting = item.get('hosting', True)
                country = item.get('countryCode', '')
                isp = item.get('isp', '')
                org = item.get('org', '')
                as_name = item.get('as', '')
                ip = item.get('query')

                # 判定规则：非 Hosting，且组织名中无云厂商/机房关键词
                org_full = f"{isp} {org} {as_name}".lower()
                has_datacenter_kw = any(kw in org_full for kw in BLOCKED_KEYWORDS)

                if (not is_hosting) and (not has_datacenter_kw):
                    matched_node = ip_map.get(ip)
                    if matched_node:
                        matched_node['isp'] = isp
                        matched_node['country'] = country
                        clean_residential_nodes.append(matched_node)
                        print(f"  [+] 命中纯正家宽: {country} | {ip}:{matched_node['port']} ({matched_node['type']}) - {isp}")
    except Exception as e:
        print(f"批量验证 IP 属性失败: {e}")

    return clean_residential_nodes


# ---------------- 主程序 ----------------
def main():
    print("=== 开始执行多源住宅 IP 采集与筛选 ===")
    
    # 1. 多源并发采集
    raw_candidates = []
    raw_candidates.extend(fetch_source_vpngate())
    raw_candidates.extend(fetch_source_geonode())
    raw_candidates.extend(fetch_source_github_socks5())

    # 根据 IP 去重
    seen_ips = set()
    unique_candidates = []
    for c in raw_candidates:
        if c['ip'] not in seen_ips:
            seen_ips.add(c['ip'])
            unique_candidates.append(c)

    if not unique_candidates:
        print("未抓取到有效候选节点。")
        return

    # 2. TCP 端口测活
    alive_nodes = filter_alive_nodes(unique_candidates)

    # 3. 批量属性过滤
    final_nodes = batch_validate_residential(alive_nodes)

    # 截取前 N 个优质节点
    final_nodes = final_nodes[:MAX_FINAL_NODES]
    print(f"\n筛选完成！共产生 {len(final_nodes)} 个高纯净住宅/原生节点。")

    # 4. 持久化存储结果
    with open("residential_nodes.json", "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
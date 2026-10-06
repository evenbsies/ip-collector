import base64
import csv
import json
import os
import re
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
EU_US_COUNTRIES = {'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'SE', 'PL', 'CH'}
ASIA_COUNTRIES = {'JP', 'KR', 'TW', 'HK', 'SG', 'MY', 'TH', 'VN', 'PH', 'ID', 'IN'}
ALL_TARGETS = EU_US_COUNTRIES | ASIA_COUNTRIES

BLOCKED_KEYWORDS = [
    'hosting', 'datacenter', 'cloud', 'server', 'digitalocean', 
    'linode', 'vultr', 'amazon', 'aws', 'google', 'microsoft', 
    'alibaba', 'tencent', 'oracle', 'ovh'
]
BLOCKED_SUBNETS = ['219.100.37.']  # 过滤 VPNGate 官方机房

# 后台精选输出配额（少而精，保障质量）
FINAL_MAX_EU_US = 8   # 欧美优选 8 个
FINAL_MAX_ASIA = 10   # 亚洲优选 10 个

OUTPUT_FILE = "residential_nodes.json"
# ==========================================


def load_existing_nodes():
    """读取历史节点池以实现状态继承"""
    if not os.path.exists(OUTPUT_FILE):
        return {}
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {f"{node['ip']}:{node['port']}": node for node in data if 'ip' in node and 'port' in node}
    except Exception:
        return {}


def fetch_source_vpngate():
    """在线抓取全网候选节点"""
    url = "https://www.vpngate.net/api/iphone/"
    candidates = {}
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            lines = [l.decode('utf-8', errors='ignore').strip() for l in resp.readlines()]
            if len(lines) > 2:
                reader = csv.reader(lines[1:])
                for row in reader:
                    if len(row) < 15: continue
                    ip, country, config_b64 = row[1], row[6].upper(), row[-1]
                    if country not in ALL_TARGETS: continue
                    if any(ip.startswith(s) for s in BLOCKED_SUBNETS): continue
                    
                    try:
                        cfg = base64.b64decode(config_b64).decode('utf-8', errors='ignore')
                        proto = re.search(r'^\s*proto\s+(tcp|udp)', cfg, re.M | re.I)
                        if not proto or proto.group(1).lower() != 'tcp': continue
                        
                        port_m = re.search(r'^\s*remote\s+[\d\.]+\s+(\d+)', cfg, re.M | re.I)
                        port = int(port_m.group(1)) if port_m else 443
                        
                        key = f"{ip}:{port}"
                        candidates[key] = {
                            'ip': ip, 'port': port, 'country': country,
                            'type': 'openvpn', 'config_b64': config_b64
                        }
                    except Exception:
                        continue
    except Exception as e:
        print(f"[VPNGate] 抓取失败: {e}")
    return candidates


def check_port_with_latency(node, timeout=2.5):
    """探针测活并记录实际 TCP 握手延迟（毫秒）"""
    ip, port = node['ip'], node['port']
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = (sock.connect_ex((ip, port)) == 0)
        sock.close()
        latency = int((time.time() - start) * 1000)
        return (node, ok, latency)
    except Exception:
        return (node, False, 9999)


def batch_validate_new_ips(new_nodes):
    """对新加入的节点验证原生家宽 ISP 属性"""
    if not new_nodes: return []
    unique_nodes = {n['ip']: n for n in new_nodes}
    unique_ips = list(unique_nodes.keys())[:100]
    
    post_payload = json.dumps([
        {"query": ip, "fields": "status,countryCode,isp,org,as,hosting,query"} 
        for ip in unique_ips
    ]).encode('utf-8')

    req = urllib.request.Request(
        "http://ip-api.com/batch", 
        data=post_payload, 
        headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    )

    verified = []
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

                org_full = f"{isp} {org} {as_name}".lower()
                has_datacenter_kw = any(kw in org_full for kw in BLOCKED_KEYWORDS)

                if (not is_hosting) and (not has_datacenter_kw):
                    node = unique_nodes.get(ip)
                    if node:
                        node['isp'] = isp
                        node['country'] = country
                        verified.append(node)
                        print(f"  [+] 验证家宽: {country} | {ip}:{node['port']} ({node.get('latency', 0)}ms) - {isp}")
    except Exception as e:
        print(f"属性批量查询失败: {e}")
    return verified


def main():
    print("=== 开始执行后台住宅 IP 精密测速与筛选 ===")
    historical_pool = load_existing_nodes()
    online_candidates = fetch_source_vpngate()

    all_to_check = {}
    for k, v in historical_pool.items(): all_to_check[k] = v
    for k, v in online_candidates.items():
        if k in all_to_check:
            all_to_check[k]['config_b64'] = v['config_b64']
        else:
            all_to_check[k] = v

    print(f"聚合待测候选: {len(all_to_check)} 个")

    # 并发测速测活
    alive_known = []
    alive_new = []
    with ThreadPoolExecutor(max_workers=45) as pool:
        results = pool.map(check_port_with_latency, all_to_check.values())
        for node, ok, latency in results:
            if ok:
                node['latency'] = latency
                if 'isp' in node and node['isp']:
                    alive_known.append(node)
                else:
                    alive_new.append(node)

    # 验证新发现节点的 ISP
    new_verified = batch_validate_new_ips(alive_new)

    # 合并存活列表
    total_active = alive_known + new_verified

    # 核心：按后台实际测得的 TCP 延迟升序排序（低延迟优先）
    total_active.sort(key=lambda x: x.get('latency', 9999))

    eu_us_final = []
    asia_final = []

    for node in total_active:
        country = node.get('country', '')
        if country in EU_US_COUNTRIES:
            if len(eu_us_final) < FINAL_MAX_EU_US:
                eu_us_final.append(node)
        elif country in ASIA_COUNTRIES:
            if len(asia_final) < FINAL_MAX_ASIA:
                asia_final.append(node)

    final_pool = asia_final + eu_us_final

    # 熔断安全阀：防止网络异常导致输出空文件破坏前端
    if len(final_pool) < 5:
        print("【安全熔断】本次可用节点数低于 5 个，疑似接口抖动！放弃写入，保留旧文件。")
        return

    print(f"\n筛选成功！精选活跃住宅节点: 亚洲 {len(asia_final)} 个 | 欧美 {len(eu_us_final)} 个 (总计 {len(final_pool)} 个)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_pool, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()

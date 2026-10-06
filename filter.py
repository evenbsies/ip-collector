import base64
import csv
import json
import os
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
# 欧美目标国家列表
EU_US_COUNTRIES = {'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'SE', 'PL', 'CH', 'RU', 'UA'}
# 亚洲目标国家列表
ASIA_COUNTRIES = {'JP', 'KR', 'TW', 'HK', 'SG', 'MY', 'TH', 'VN', 'PH', 'ID', 'IN'}
ALL_TARGETS = EU_US_COUNTRIES | ASIA_COUNTRIES

# 严格过滤已知机房/托管服务商特征
BLOCKED_KEYWORDS = [
    'hosting', 'datacenter', 'cloud', 'server', 'digitalocean', 
    'linode', 'vultr', 'amazon', 'aws', 'google', 'microsoft', 
    'alibaba', 'tencent', 'oracle', 'ovh'
]
BLOCKED_SUBNETS = ['219.100.37.']  # 过滤 VPNGate 官方机房

# 蓄水池最大容量上限
MAX_EU_US_NODES = 35
MAX_ASIA_NODES = 35

OUTPUT_FILE = "residential_nodes.json"
# ==========================================


def load_existing_nodes():
    """读取上一次成功运行保存的历史节点池"""
    if not os.path.exists(OUTPUT_FILE):
        return {}
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # 以 ip:port 作为唯一键缓存
            return {f"{node['ip']}:{node['port']}": node for node in data if 'ip' in node and 'port' in node}
    except Exception as e:
        print(f"读取历史节点池失败: {e}")
        return {}


def fetch_source_vpngate():
    """全量抓取 VPNGate 并提取全部 OpenVPN TCP 候选"""
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
                            'ip': ip,
                            'port': port,
                            'country': country,
                            'type': 'openvpn',
                            'config_b64': config_b64,
                            'fail_count': 0
                        }
                    except Exception:
                        continue
    except Exception as e:
        print(f"[VPNGate] 抓取失败: {e}")
        
    print(f"[在线数据] 本轮抓取到 {len(candidates)} 个有效 TCP 节点")
    return candidates


def check_port(node, timeout=3.0):
    """TCP 连通性测活"""
    ip, port = node['ip'], node['port']
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = (sock.connect_ex((ip, port)) == 0)
        sock.close()
        return (node, ok)
    except:
        return (node, False)


def batch_validate_new_ips(new_nodes):
    """仅对新发现的候选节点进行批量 IP 属性查询"""
    if not new_nodes:
        return []
    
    unique_nodes = {n['ip']: n for n in new_nodes}
    unique_ips = list(unique_nodes.keys())
    
    chunk_size = 100
    chunks = [unique_ips[i:i + chunk_size] for i in range(0, min(len(unique_ips), 200), chunk_size)]
    
    verified = []
    for idx, chunk in enumerate(chunks, 1):
        print(f"正在对新节点执行第 {idx}/{len(chunks)} 批纯净度验证 (共 {len(chunk)} 个)...")
        post_payload = json.dumps([
            {"query": ip, "fields": "status,countryCode,isp,org,as,hosting,query"} 
            for ip in chunk
        ]).encode('utf-8')

        req = urllib.request.Request(
            "http://ip-api.com/batch", 
            data=post_payload, 
            headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
        )

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
                            print(f"  [+] 新入池家宽: {country} | {ip}:{node['port']} - {isp}")
        except Exception as e:
            print(f"新节点第 {idx} 批属性查询失败: {e}")

    return verified


def main():
    print("=== 开始执行增量蓄水池住宅 IP 筛选 ===")
    
    # 1. 加载历史节点
    historical_pool = load_existing_nodes()
    print(f"[蓄水池状态] 历史继承节点数: {len(historical_pool)} 个")
    
    # 2. 抓取当前在线候选
    online_candidates = fetch_source_vpngate()
    
    # 3. 聚合去重：历史存活节点 + 新发现节点
    all_to_check = {}
    
    # 先载入老节点（自带 isp 属性）
    for key, node in historical_pool.items():
        all_to_check[key] = node

    # 载入新抓取节点（如果老节点库已有，则刷新配置；如果没有，标记为待验证）
    for key, node in online_candidates.items():
        if key in all_to_check:
            # 刷新 Base64 证书配置，保留原有 isp
            all_to_check[key]['config_b64'] = node['config_b64']
        else:
            all_to_check[key] = node

    print(f"[总测活队列] 包含历史与新节点共: {len(all_to_check)} 个")

    # 4. 全量并发 TCP 连通性测活
    alive_known_nodes = []   # 测通且已有 ISP 的老节点
    alive_new_nodes = []     # 测通但需要查验 ISP 的新节点
    unreachable_nodes = []

    with ThreadPoolExecutor(max_workers=45) as pool:
        results = pool.map(check_port, all_to_check.values())
        for node, ok in results:
            if ok:
                node['fail_count'] = 0
                if 'isp' in node and node['isp']:
                    alive_known_nodes.append(node)
                else:
                    alive_new_nodes.append(node)
            else:
                node['fail_count'] = node.get('fail_count', 0) + 1
                unreachable_nodes.append(node)

    print(f"测活结果: 存活老节点 {len(alive_known_nodes)} 个 | 存活新节点 {len(alive_new_nodes)} 个 | 离线 {len(unreachable_nodes)} 个")

    # 5. 仅针对存活的“新节点”走 API 查询
    newly_verified_nodes = batch_validate_new_ips(alive_new_nodes)

    # 6. 容错保留：对离线节点进行熔断判定（连续失联小于 3 次的继续宽限保留）
    grace_nodes = [
        n for n in unreachable_nodes 
        if n.get('fail_count', 0) < 3 and 'isp' in n and n['isp']
    ]
    print(f"[熔断保护] 宽限保留 {len(grace_nodes)} 个暂时失联节点以防抖动")

    # 7. 合并所有可用节点并分类控额
    total_active_pool = alive_known_nodes + newly_verified_nodes + grace_nodes

    eu_us_final = []
    asia_final = []

    # 优先录入刚刚测活成功的，再录入宽限节点
    total_active_pool.sort(key=lambda x: x.get('fail_count', 0))

    for node in total_active_pool:
        country = node.get('country', '')
        if country in EU_US_COUNTRIES:
            if len(eu_us_final) < MAX_EU_US_NODES:
                eu_us_final.append(node)
        elif country in ASIA_COUNTRIES:
            if len(asia_final) < MAX_ASIA_NODES:
                asia_final.append(node)

    final_result = eu_us_final + asia_final
    print(f"\n=== 本轮筛选汇总 ===")
    print(f"欧美住宅节点: {len(eu_us_final)} 个")
    print(f"亚洲住宅节点: {len(asia_final)} 个")
    print(f"总计保留输出: {len(final_result)} 个")

    # 8. 持久化回写
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_result, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()

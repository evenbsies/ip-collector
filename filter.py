import base64
import csv
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
# 欧美目标国家列表
EU_US_COUNTRIES = {'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'SE', 'PL', 'CH'}
# 亚洲目标国家列表（扩充了港、新、东南亚等）
ASIA_COUNTRIES = {'JP', 'KR', 'TW', 'HK', 'SG', 'MY', 'TH', 'VN', 'PH', 'IN'}

# 严格过滤已知机房/云服务商特征
BLOCKED_KEYWORDS = [
    'hosting', 'datacenter', 'cloud', 'server', 'digitalocean', 
    'linode', 'vultr', 'amazon', 'aws', 'google', 'microsoft', 
    'alibaba', 'tencent', 'oracle', 'ovh', 'public-vpn', 'vpngate'
]
BLOCKED_SUBNETS = ['219.100.37.']  # VPNGate 官方自建机房网段

# 最终保留配额（平衡欧美与亚洲）
TARGET_EU_US_MAX = 12   # 欧美保留数量上限
TARGET_ASIA_MAX = 12    # 亚洲保留数量上限
# ==========================================


def fetch_source_vpngate():
    """获取公开家宽列表并按亚洲/欧美平衡划分候选池"""
    url = "https://www.vpngate.net/api/iphone/"
    eu_us_raw = []
    asia_raw = []
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = [l.decode('utf-8', errors='ignore').strip() for l in resp.readlines()]
            if len(lines) > 2:
                reader = csv.reader(lines[1:])
                for row in reader:
                    if len(row) < 15: continue
                    host_name, ip, country, config_b64 = row[0], row[1], row[6].upper(), row[-1]
                    
                    # 过滤机房关键词与黑名单网段
                    if any(ip.startswith(s) for s in BLOCKED_SUBNETS): continue
                    if any(kw in host_name.lower() for kw in BLOCKED_KEYWORDS): continue
                    
                    # 仅保留 OpenVPN TCP 协议
                    try:
                        cfg = base64.b64decode(config_b64).decode('utf-8', errors='ignore')
                        proto = re.search(r'^\s*proto\s+(tcp|udp)', cfg, re.M | re.I)
                        if not proto or proto.group(1).lower() != 'tcp': continue
                        port_m = re.search(r'^\s*remote\s+[\d\.]+\s+(\d+)', cfg, re.M | re.I)
                        port = port_m.group(1) if port_m else "443"
                        
                        node = {
                            'ip': ip, 'port': int(port), 'country': country, 
                            'type': 'openvpn', 'config_b64': config_b64
                        }
                        
                        if country in EU_US_COUNTRIES:
                            eu_us_raw.append(node)
                        elif country in ASIA_COUNTRIES:
                            asia_raw.append(node)
                    except Exception:
                        continue
    except Exception as e:
        print(f"[VPNGate] 抓取失败: {e}")
        
    print(f"[抓取统计] 欧美候选: {len(eu_us_raw)} 个 | 亚洲候选: {len(asia_raw)} 个")
    
    # 核心平衡机制：为避免某一方独占 100 个检测配额，各截取前 50 个混合送检
    selected_pool = eu_us_raw[:50] + asia_raw[:50]
    return selected_pool


def check_port(node, timeout=2.0):
    """TCP 握手探针：过滤掉不可连通的死节点"""
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
    print(f"开始并发 TCP 测活 ({len(nodes)} 个平衡候选)...")
    alive = []
    with ThreadPoolExecutor(max_workers=35) as pool:
        results = pool.map(check_port, nodes)
        for r in results:
            if r: alive.append(r)
    print(f"TCP 连通测活成功: {len(alive)} 个")
    return alive


def batch_validate_residential(alive_nodes):
    """批量查询 IP 属性并分别装入欧美/亚洲配额池"""
    if not alive_nodes: return []
    
    ip_map = {node['ip']: node for node in alive_nodes}
    unique_ips = list(ip_map.keys())[:100]  # ip-api 批量单次上限 100
    
    post_payload = json.dumps([
        {"query": ip, "fields": "status,countryCode,isp,org,as,hosting,query"} 
        for ip in unique_ips
    ]).encode('utf-8')

    req = urllib.request.Request(
        "http://ip-api.com/batch", 
        data=post_payload, 
        headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    )

    eu_us_final = []
    asia_final = []

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

                # 必须是非机房且无云厂商关键词的真实宽带
                if (not is_hosting) and (not has_datacenter_kw):
                    matched_node = ip_map.get(ip)
                    if matched_node:
                        matched_node['isp'] = isp
                        matched_node['country'] = country
                        
                        # 按所属区域入池
                        if country in EU_US_COUNTRIES:
                            if len(eu_us_final) < TARGET_EU_US_MAX:
                                eu_us_final.append(matched_node)
                                print(f"  [+] 欧美家宽: {country} | {ip}:{matched_node['port']} - {isp}")
                        elif country in ASIA_COUNTRIES:
                            if len(asia_final) < TARGET_ASIA_MAX:
                                asia_final.append(matched_node)
                                print(f"  [+] 亚洲家宽: {country} | {ip}:{matched_node['port']} - {isp}")
    except Exception as e:
        print(f"批量验证 IP 属性失败: {e}")

    # 合并输出结果：包含完整的欧美与亚洲节点
    return eu_us_final + asia_final


def main():
    print("=== 开始执行全网住宅 IP 采集（欧美 + 亚洲 平衡模式） ===")
    
    # 1. 抓取与平衡初筛
    candidates = fetch_source_vpngate()
    if not candidates:
        print("未抓取到有效候选节点。")
        return

    # 2. 并发测活
    alive_nodes = filter_alive_nodes(candidates)

    # 3. 属性校验与配额分配
    final_nodes = batch_validate_residential(alive_nodes)

    print(f"\n筛选完成！共产生 {len(final_nodes)} 个高纯净住宅节点。")

    # 4. 保存结果
    with open("residential_nodes.json", "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
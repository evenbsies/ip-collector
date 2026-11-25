# ip-collector

住宅代理 IP 精选池：

- `residential_nodes.json`：VPN Gate OpenVPN/SSTP 节点，`filter.py` + `auto_filter.yml` 每 4 小时刷新。
- `residential_socks.txt`：Geonode / ProxyScrape / GitHub 4 个 socks5 清单，`socks_pool.py` + `socks_pool.yml` 每 2 小时抓取、SOCKS5 拨测、ip-api ASN 验真后输出面板链式行。

# Xray / sing-box 一键 Ban 回国流量脚本

自动探测本机部署的 **Xray** 或 **sing-box** 内核及配置文件路径，在保留原有缩进和节点配置的前提下，向路由表头部安全注入拦截规则（将 `geoip:cn`、`geosite:cn` 及内网私有 IP 指向 `block` 出站），防止回国流量滥用或触发风控。

---

## 一键运行命令

### 1. 标准运行（自带防 CDN 缓存与执行后自动清理）
```bash
rm -f ban_cn.sh && curl -sL "https://raw.githubusercontent.com/pansir0290/bancn/main/ban_cn.sh?v=$(date +%s)" -o ban_cn.sh && chmod +x ban_cn.sh && ./ban_cn.sh && rm -f ban_cn.sh

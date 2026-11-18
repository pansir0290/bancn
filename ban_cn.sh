#!/bin/bash
trap 'rm -f /tmp/ban_cn_test.tmp' EXIT
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] 请使用 root 权限运行"
  exit 1
fi

echo "[+] 1. 检测 GitHub 连通性以选择最佳规则集源..."
GITHUB_PREFIX=""
if ! curl -sI --connect-timeout 3 https://raw.githubusercontent.com >/dev/null 2>&1; then
  echo "[!] 直连 GitHub 超时，自动启用镜像加速前缀..."
  GITHUB_PREFIX="https://gh-proxy.com/"
else
  echo "[✔] 直连 GitHub 正常。"
fi

echo "[+] 2. 深度探测本机 Xray / sing-box 配置文件..."
FOUND_FILES=()

while IFS= read -r cmdline; do
  cfg=$(echo "$cmdline" | grep -oE '(-c|--config|-confdir)[= ]+[^ ]+' | awk '{print $NF}' | tr -d '"' | tr -d "'")
  if [ -f "$cfg" ]; then
    [[ " ${FOUND_FILES[*]} " =~ " ${cfg} " ]] || FOUND_FILES+=("$cfg")
  fi
done < <(ps -ef | grep -E "xray|sing-box" | grep -v grep)

DEFAULT_PATHS=(
  "/usr/local/etc/xray/config.json"
  "/etc/xray/config.json"
  "/etc/sing-box/config.json"
  "/etc/v2ray-agent/sing-box/conf/config.json"
  "/etc/v2ray-agent/xray/conf/config.json"
)
for p in "${DEFAULT_PATHS[@]}"; do
  if [ -f "$p" ]; then
    [[ " ${FOUND_FILES[*]} " =~ " ${p} " ]] || FOUND_FILES+=("$p")
  fi
done

if [ ${#FOUND_FILES[@]} -eq 0 ]; then
  echo "[-] 未检测到任何 Xray 或 sing-box 配置文件。"
  exit 1
fi

SB_VER_STR="0.0.0"
if command -v sing-box >/dev/null 2>&1; then
  SB_VER_STR=$(sing-box version | head -n1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
  echo "[+] 检测到 sing-box 版本: $SB_VER_STR"
fi

for config_file in "${FOUND_FILES[@]}"; do
  echo "------------------------------------------------"
  echo "[*] 处理文件: $config_file"
  BACKUP_FILE="${config_file}.bak_$(date +%Y%m%d%H%M%S)"
  cp "$config_file" "$BACKUP_FILE"

  python3 - "$config_file" "$SB_VER_STR" "$GITHUB_PREFIX" << 'PYEOF'
import json, re, sys

path = sys.argv[1]
sb_ver_str = sys.argv[2]
gh_prefix = sys.argv[3]

def ver_tuple(v):
    parts = [int(x) for x in re.findall(r'\d+', v)]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

sb_ver = ver_tuple(sb_ver_str)
sb_is_new = sb_ver >= (1, 8, 0)

with open(path, "r", encoding="utf-8") as f:
    raw = f.read()

# 安全剥离注释（使用 (?<!:) 避免误伤 https:// 中的双斜杠）及尾随逗号
clean_json = re.sub(r'(?<!:)//.*?$|/\*.*?\*/', '', raw, flags=re.MULTILINE | re.DOTALL)
clean_json = re.sub(r',\s*([\]}])', r'\1', clean_json)

try:
    data = json.loads(clean_json, strict=False)
except Exception as e:
    print(f"[-] JSON 解析失败 ({e})，跳过此文件。")
    sys.exit(2)

is_singbox = ("route" in data) or any(
    isinstance(i, dict) and "type" in i and "protocol" not in i 
    for i in data.get("inbounds", [])
)

data.setdefault("outbounds", [])
has_block = any(
    ob.get("tag") == "block" or ob.get("protocol") == "blackhole" or ob.get("type") == "block"
    for ob in data["outbounds"]
)
if not has_block:
    if is_singbox:
        data["outbounds"].append({"type": "block", "tag": "block"})
    else:
        data["outbounds"].append({"protocol": "blackhole", "tag": "block"})

if is_singbox:
    data.setdefault("route", {})
    data["route"].setdefault("rules", [])
    
    if sb_is_new:
        data["route"].setdefault("rule_set", [])
        
        if sb_ver >= (1, 14, 0):
            for rs in data["route"]["rule_set"]:
                if rs.get("tag") in ("geoip-cn", "geosite-cn") and "download_detour" in rs:
                    del rs["download_detour"]

        existing_tags = {rs.get("tag") for rs in data["route"]["rule_set"]}
        if "geoip-cn" not in existing_tags:
            rs_geoip = {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": f"{gh_prefix}https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
            }
            if sb_ver < (1, 14, 0):
                rs_geoip["download_detour"] = "direct"
            data["route"]["rule_set"].append(rs_geoip)

        if "geosite-cn" not in existing_tags:
            rs_geosite = {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": f"{gh_prefix}https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
            }
            if sb_ver < (1, 14, 0):
                rs_geosite["download_detour"] = "direct"
            data["route"]["rule_set"].append(rs_geosite)
        
        already = any("geoip-cn" in r.get("rule_set", []) for r in data["route"]["rules"])
        if not already:
            new_rules = [
                {"ip_is_private": True, "outbound": "block"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "block"}
            ]
            data["route"]["rules"] = new_rules + data["route"]["rules"]
            print(f"[+] 已注入 sing-box ({sb_ver_str} rule_set) 拦截规则")
        else:
            print(f"[i] sing-box ({sb_ver_str}) 规则已存在并已清理过时参数")
    else:
        already = any("cn" in r.get("geoip", []) for r in data["route"]["rules"])
        if not already:
            new_rules = [
                {"geoip": ["private", "cn"], "outbound": "block"},
                {"geosite": ["cn"], "outbound": "block"}
            ]
            data["route"]["rules"] = new_rules + data["route"]["rules"]
            print(f"[+] 已注入 sing-box ({sb_ver_str} 旧版 geoip) 拦截规则")
else:
    data.setdefault("routing", {})
    data["routing"]["domainStrategy"] = "IPIfNonMatch"
    data["routing"].setdefault("rules", [])
    
    already = any("geoip:cn" in r.get("ip", []) for r in data["routing"]["rules"])
    if not already:
        new_rules = [
            {"type": "field", "ip": ["geoip:private", "geoip:cn"], "outboundTag": "block"},
            {"type": "field", "domain": ["geosite:cn"], "outboundTag": "block"}
        ]
        data["routing"]["rules"] = new_rules + data["routing"]["rules"]
        print("[+] 已注入 Xray 拦截规则 (IPIfNonMatch)")
    else:
        print("[i] Xray 规则已存在，无需重复注入")

indent = 2
for line in raw.splitlines():
    if line.startswith("    "):
        indent = 4
        break
    elif line.startswith("  "):
        indent = 2
        break

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=indent)
PYEOF

  PY_RET=$?
  if [ $PY_RET -ne 0 ]; then
    cp "$BACKUP_FILE" "$config_file"
    continue
  fi

  if grep -q '"route"' "$config_file"; then
    if sing-box check -c "$config_file" >/dev/null 2>&1; then
      echo "[✔] sing-box 校验通过，正在重启服务..."
      systemctl list-units --type=service --state=running | grep -oE 'sing-box[^ ]*\.service' | xargs -r systemctl restart
    else
      echo "[-] ❌ sing-box 校验失败，已自动回滚原配置！"
      sing-box check -c "$config_file" || true
      cp "$BACKUP_FILE" "$config_file"
    fi
  else
    if xray run -test -c "$config_file" >/dev/null 2>&1; then
      echo "[✔] Xray 校验通过，正在重启服务..."
      systemctl list-units --type=service --state=running | grep -oE 'xray[^ ]*\.service' | xargs -r systemctl restart
    else
      echo "[-] ❌ Xray 校验失败，已自动回滚原配置！"
      xray run -test -c "$config_file" || true
      cp "$BACKUP_FILE" "$config_file"
    fi
  fi
done
echo "------------------------------------------------"
echo "[✔] 全部处理完成。"

#!/bin/bash
trap 'rm -f /tmp/ban_cn_test.tmp /tmp/geoip.dat /tmp/geosite.dat' EXIT
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

# 探测实际存在的内核二进制文件（避免处理未安装内核的残余面板配置）
XRAY_BIN=$(command -v xray 2>/dev/null || [ -x "/usr/local/bin/xray" ] && echo "/usr/local/bin/xray" || [ -x "/etc/v2ray-agent/xray/xray" ] && echo "/etc/v2ray-agent/xray/xray" || echo "")
SB_BIN=$(command -v sing-box 2>/dev/null || [ -x "/usr/local/bin/sing-box" ] && echo "/usr/local/bin/sing-box" || [ -x "/etc/v2ray-agent/sing-box/sing-box" ] && echo "/etc/v2ray-agent/sing-box/sing-box" || echo "")

echo "[+] 2. 深度探测本机 Xray / sing-box 配置文件..."
FOUND_FILES=()

while IFS= read -r cmdline; do
  cfg=$(echo "$cmdline" | grep -oE '(-c|--config|-confdir)[= ]+[^ ]+' | awk '{print $NF}' | tr -d '"' | tr -d "'")
  if [ -f "$cfg" ]; then
    [[ " ${FOUND_FILES[*]} " =~ " ${cfg} " ]] || FOUND_FILES+=("$cfg")
  fi
done < <(ps -ef | grep -E "xray|sing-box" | grep -v grep)

if [ -n "$XRAY_BIN" ]; then
  for p in "/usr/local/etc/xray/config.json" "/etc/xray/config.json" "/etc/v2ray-agent/xray/conf/config.json"; do
    if [ -f "$p" ]; then
      [[ " ${FOUND_FILES[*]} " =~ " ${p} " ]] || FOUND_FILES+=("$p")
    fi
  done
fi

if [ -n "$SB_BIN" ]; then
  for p in "/etc/sing-box/config.json" "/usr/local/etc/sing-box/config.json" "/etc/v2ray-agent/sing-box/conf/config.json"; do
    if [ -f "$p" ]; then
      [[ " ${FOUND_FILES[*]} " =~ " ${p} " ]] || FOUND_FILES+=("$p")
    fi
  done
fi

if [ ${#FOUND_FILES[@]} -eq 0 ]; then
  echo "[-] 未检测到任何有效的 Xray 或 sing-box 配置文件。"
  exit 1
fi

SB_VER_STR="0.0.0"
if [ -n "$SB_BIN" ]; then
  SB_VER_STR=$("$SB_BIN" version | head -n1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
  echo "[+] 检测到 sing-box ($SB_BIN) 版本: $SB_VER_STR"
fi

XRAY_ASSET_DIR=$(dirname "${XRAY_BIN:-/usr/local/bin/xray}")

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

direct_tag = "direct"
for ob in data["outbounds"]:
    if ob.get("type") == "direct" or ob.get("protocol") == "freedom":
        if ob.get("tag"):
            direct_tag = ob["tag"]
            break

if is_singbox:
    data.setdefault("route", {})
    data["route"].setdefault("rules", [])
    
    has_whitelist = any("gstatic.com" in r.get("domain_suffix", []) for r in data["route"]["rules"])
    if not has_whitelist:
        data["route"]["rules"].insert(0, {
            "domain_suffix": ["gstatic.com", "googleapis.com"],
            "outbound": direct_tag
        })

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
                rs_geoip["download_detour"] = direct_tag
            data["route"]["rule_set"].append(rs_geoip)

        if "geosite-cn" not in existing_tags:
            rs_geosite = {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": f"{gh_prefix}https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
            }
            if sb_ver < (1, 14, 0):
                rs_geosite["download_detour"] = direct_tag
            data["route"]["rule_set"].append(rs_geosite)
        
        already = any("geoip-cn" in r.get("rule_set", []) for r in data["route"]["rules"])
        if not already:
            data["route"]["rules"].insert(1, {"ip_is_private": True, "outbound": "block"})
            data["route"]["rules"].insert(2, {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "block"})
            print(f"[+] 已注入 sing-box ({sb_ver_str} rule_set + 测速白名单) 拦截规则")
        else:
            print(f"[i] sing-box ({sb_ver_str}) 规则已存在，已补全测速白名单")
    else:
        already = any("cn" in r.get("geoip", []) for r in data["route"]["rules"])
        if not already:
            data["route"]["rules"].insert(1, {"geoip": ["private", "cn"], "outbound": "block"})
            data["route"]["rules"].insert(2, {"geosite": ["cn"], "outbound": "block"})
            print(f"[+] 已注入 sing-box ({sb_ver_str} 旧版 geoip + 测速白名单) 拦截规则")
        else:
            print(f"[i] sing-box ({sb_ver_str}) 规则已存在，已补全测速白名单")
else:
    data.setdefault("routing", {})
    data["routing"]["domainStrategy"] = "IPIfNonMatch"
    data["routing"].setdefault("rules", [])
    
    has_whitelist = any("domain:gstatic.com" in r.get("domain", []) for r in data["routing"]["rules"])
    if not has_whitelist:
        data["routing"]["rules"].insert(0, {
            "type": "field",
            "domain": ["domain:gstatic.com", "domain:googleapis.com"],
            "outboundTag": direct_tag
        })

    already = any("geoip:cn" in r.get("ip", []) for r in data["routing"]["rules"])
    if not already:
        data["routing"]["rules"].insert(1, {"type": "field", "ip": ["geoip:private", "geoip:cn"], "outboundTag": "block"})
        data["routing"]["rules"].insert(2, {"type": "field", "domain": ["geosite:cn"], "outboundTag": "block"})
        print("[+] 已注入 Xray 拦截规则 (IPIfNonMatch + 测速白名单)")
    else:
        print("[i] Xray 规则已存在，已补全测速白名单")

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
    if [ -n "$SB_BIN" ] && "$SB_BIN" check -c "$config_file" >/dev/null 2>&1; then
      echo "[✔] sing-box 校验通过，正在重启服务..."
      systemctl list-units --type=service --state=running | grep -oE 'sing-box[^ ]*\.service' | xargs -r systemctl restart
    else
      echo "[-] ❌ sing-box 校验失败或未安装，已自动回滚原配置！"
      [ -n "$SB_BIN" ] && "$SB_BIN" check -c "$config_file" || true
      cp "$BACKUP_FILE" "$config_file"
    fi
  else
    [ -L "$XRAY_ASSET_DIR" ] && [ ! -e "$XRAY_ASSET_DIR" ] && rm -f "$XRAY_ASSET_DIR"
    mkdir -p "$XRAY_ASSET_DIR"
    for dat in geoip.dat geosite.dat; do
      if [ ! -s "$XRAY_ASSET_DIR/$dat" ]; then
        echo "[!] 检测到缺少 $dat，正在通过 /tmp 中转下载到 $XRAY_ASSET_DIR ..."
        curl -fL "${GITHUB_PREFIX}https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/${dat}" -o "/tmp/${dat}" && mv -f "/tmp/${dat}" "$XRAY_ASSET_DIR/$dat" || true
      fi
    done

    if [ -n "$XRAY_BIN" ] && "$XRAY_BIN" run -test -c "$config_file" >/dev/null 2>&1; then
      echo "[✔] Xray 校验通过，正在重启服务..."
      systemctl list-units --type=service --state=running | grep -oE 'xray[^ ]*\.service' | xargs -r systemctl restart
    else
      echo "[-] ❌ Xray 校验失败，已自动回滚原配置！"
      [ -n "$XRAY_BIN" ] && "$XRAY_BIN" run -test -c "$config_file" || true
      cp "$BACKUP_FILE" "$config_file"
    fi
  fi
done
echo "------------------------------------------------"
echo "[✔] 全部处理完成。"

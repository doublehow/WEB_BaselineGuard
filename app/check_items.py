"""檢查項目錄:對映 ucc_check.sh v2.1.1 的全部檢查項(供「檢查項目」頁與停用過濾)。

- 每項:id(腳本內穩定 ID)、fams(適用系列)、cat(章節)、desc(檢查內容)、
  ref(出處;精確條次以腳本標註為準,其餘標到章級,不虛構條號)。
- 新增/調整腳本檢查項時,本目錄需同步維護。
- 動態 ID(如 mnt-/tmp、cron-dir-*)在此逐一展開,與腳本實際輸出一致。
"""
from __future__ import annotations

# 歸組清單由設備類型註冊表提供(Linux 兩組 + 網路設備各型;見 devtypes.py)
from app.devtypes import FAMILY_LABEL as FAMILIES  # noqa: F401
from app.devtypes import IMPLEMENTED_FAMILIES  # noqa: F401

BOTH = ("deb", "rpm")
DEB = ("deb",)
RPM = ("rpm",)

# Linux 出處條次基準(2026-08-24 依 sample/ 內 CIS 原始 PDF 逐條核對):
# deb = CIS Ubuntu 22.04 v2.0.0;rpm = CIS RHEL 9 v2.0.0(Rocky 9 v2.0.0 同號)。
# 「U22 x / R9 y」= 兩系條次不同;單一號碼 = 兩系同號。
# U24.04 v1.0.0 除 AIDE(6.3.1)外與 U22 同號;RHEL/Rocky 8 與 U20.04 為
# 舊世代編排(sshd 在 4.2.x / 5.1.x 位移),查舊版請對 sample/ 對應 PDF。

CATALOG: list[dict] = []


def _add(item_id: str, fams: tuple, cat: str, desc: str, ref: str) -> None:
    CATALOG.append({"id": item_id, "fams": fams, "cat": cat,
                    "desc": desc, "ref": ref})


# ── 1. 磁碟與檔案系統 ──────────────────────────────────────────
_C = "1. 磁碟與檔案系統"
for _m in ("cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"):
    _add(f"fs-mod-{_m}", BOTH, _C,
         f"檔案系統模組 {_m} 已停用(modprobe.d 明文停用且未載入)",
         "TWGCB / CIS 1.1.1")
_add("fs-mod-squashfs", BOTH, _C,
     "squashfs 模組停用(Ubuntu:snapd 相依列人工;RHEL:CIS L2 建議停用)",
     "TWGCB / CIS 1.1.1")
_add("fs-mod-usb", BOTH, _C,
     "usb-storage 模組停用(實體機建議停用;VM 可列例外)", "TWGCB / CIS 1.1.1")
for _mp in ("/tmp", "/var", "/var/log", "/var/log/audit", "/home"):
    _add(f"mnt-{_mp}", BOTH, _C,
         f"{_mp} 為獨立掛載分割(建議搭配 nodev/nosuid/noexec)",
         "TWGCB / CIS 1.1(分割掛載)")
_add("mnt-tmp-noexec", BOTH, _C,
     "/tmp 掛載含 noexec(注意對 ./script 直接執行的影響)",
     "TWGCB / CIS 1.1(分割掛載)")

# ── 2. 套件管理與完整性 ─────────────────────────────────────────
_C = "2. 套件管理與完整性"
_add("pkg-unattended", BOTH, _C,
     "安全性自動更新(deb:unattended-upgrades;rpm:dnf-automatic + timer)",
     "TWGCB / CIS 1.2(套件更新)")
_add("pkg-apt-sign", DEB, _C,
     "APT 套件庫皆含簽章驗證(無 trusted=yes 繞過)", "TWGCB / CIS 1.2")
_add("pkg-gpgcheck", RPM, _C,
     "DNF/YUM 套件庫皆含簽章驗證(無 gpgcheck=0)", "CIS RHEL 9 1.2.1.2")
_add("pkg-aide", BOTH, _C,
     "AIDE 檔案完整性工具已安裝(未裝且有 DS IM → 人工/替代措施)",
     "TWGCB / CIS 6.1.1(U24.04 為 6.3.1)")

# ── 3. 開機與程序強化 ──────────────────────────────────────────
_C = "3. 開機與程序強化"
_add("boot-grub-perm", BOTH, _C,
     "grub.cfg 權限 root:root 且 ≤600(deb:/boot/grub;rpm:/boot/grub2 或 EFI)",
     "TWGCB / CIS 1.4(開機載入器)")
_add("boot-grub-pass", BOTH, _C,
     "GRUB 開機密碼保護(deb:^password;rpm:user.cfg GRUB2_PASSWORD)",
     "TWGCB / CIS 1.4")
_add("boot-aslr", BOTH, _C, "ASLR:kernel.randomize_va_space = 2", "CIS 1.5.1")
_add("boot-suid-dump", BOTH, _C, "SUID core dump 停用:fs.suid_dumpable = 0",
     "TWGCB / CIS 1.5")
_add("boot-limits-core", BOTH, _C, "limits 設 * hard core 0(未設 → 注意)",
     "TWGCB / CIS 1.5")
_add("boot-prelink", BOTH, _C, "prelink 未安裝", "CIS U22 1.5.4(R9 無此條,prelink 已移除)")
_add("boot-ptrace", BOTH, _C, "ptrace 範圍限制:kernel.yama.ptrace_scope ≥ 1",
     "CIS 1.5.2")

# ── 4. 強制存取控制 ────────────────────────────────────────────
_C = "4. 強制存取控制(AppArmor/SELinux)"
_add("aa-active", DEB, _C, "AppArmor 服務啟用中", "TWGCB / CIS 1.3.1(AppArmor)")
_add("aa-profiles", DEB, _C, "AppArmor profiles 統計(enforce/complain)",
     "TWGCB / CIS 1.3.1.3")
_add("aa-complain", DEB, _C,
     "有 complain 模式 profile 時提示(GCB 要求 enforce)", "TWGCB / CIS 1.3.1.4")
_add("se-mode", RPM, _C, "SELinux 執行模式 = Enforcing(getenforce)",
     "CIS RHEL 9 1.3.1.5")
_add("se-config", RPM, _C, "開機設定 SELINUX=enforcing(/etc/selinux/config)",
     "CIS RHEL 9 1.3.1.4")
_add("se-policy", RPM, _C, "SELINUXTYPE = targeted 或 mls", "CIS RHEL 9 1.3.1.3")

# ── 5. 警告橫幅 ────────────────────────────────────────────────
_C = "5. 警告橫幅"
for _f in ("/etc/issue", "/etc/issue.net"):
    _add(f"banner-{_f}", BOTH, _C,
         f"{_f} 法律警語存在且不含系統資訊逸出字元(\\m \\r \\s \\v)",
         "TWGCB / CIS U22 1.6.2–1.6.3 / R9 1.7.2–1.7.3")

# ── 6. 服務管理 ────────────────────────────────────────────────
_C = "6. 服務管理"
for _p in ("vsftpd", "rsh-server", "xinetd", "cups", "rpcbind"):
    _add(f"svc-{_p}", BOTH, _C, f"非必要服務未安裝:{_p}", "TWGCB / CIS 2.1(服務)")
_add("svc-telnetd", DEB, _C, "非必要服務未安裝:telnetd", "TWGCB / CIS 2.1")
_add("svc-telnet-server", RPM, _C, "非必要服務未安裝:telnet-server",
     "TWGCB / CIS 2.1")
_add("svc-avahi-daemon", DEB, _C, "非必要服務未安裝:avahi-daemon",
     "TWGCB / CIS 2.1")
_add("svc-avahi", RPM, _C, "非必要服務未安裝:avahi", "TWGCB / CIS 2.1")
_add("svc-isc-dhcp-server", DEB, _C, "非必要服務未安裝:isc-dhcp-server",
     "TWGCB / CIS 2.1")
_add("svc-dhcp-server", RPM, _C, "非必要服務未安裝:dhcp-server", "TWGCB / CIS 2.1")
_add("svc-nfs-kernel-server", DEB, _C, "NFS 伺服器未安裝", "TWGCB / CIS 2.1")
_add("svc-nfs-server", RPM, _C,
     "NFS 伺服器服務未啟用(nfs-utils 兼作用戶端,查服務不查套件)",
     "TWGCB / CIS 2.1")
_add("svc-samba", BOTH, _C,
     "samba 伺服器未安裝(已裝 → 注意;smbclient 用戶端不在此限)",
     "TWGCB / CIS 2.1")
_add("svc-timesync", BOTH, _C,
     "時間同步服務啟用中(timesyncd / chrony / chronyd)", "TWGCB / CIS 2.3(時間)")
_add("svc-ntp-src", BOTH, _C,
     "已指定 NTP 來源(建議指向機關授時伺服器)", "TWGCB / CIS 2.3")

# ── 7. 網路核心參數 ────────────────────────────────────────────
_C = "7. 網路核心參數(sysctl)"
for _k, _v in (
    ("net.ipv4.ip_forward", 0),
    ("net.ipv4.conf.all.send_redirects", 0),
    ("net.ipv4.conf.default.send_redirects", 0),
    ("net.ipv4.conf.all.accept_redirects", 0),
    ("net.ipv4.conf.default.accept_redirects", 0),
    ("net.ipv4.conf.all.secure_redirects", 0),
    ("net.ipv4.conf.all.accept_source_route", 0),
    ("net.ipv4.conf.all.log_martians", 1),
    ("net.ipv4.icmp_echo_ignore_broadcasts", 1),
    ("net.ipv4.icmp_ignore_bogus_error_responses", 1),
    ("net.ipv4.conf.all.rp_filter", 1),
    ("net.ipv4.tcp_syncookies", 1),
):
    _add(f"net-{_k}", BOTH, _C, f"{_k} = {_v}", "TWGCB / CIS 3.3(網路參數)")
_add("net-ipv6", BOTH, _C,
     "IPv6 於核心層整體停用(GRUB ipv6.disable=1;未停 → 人工逐項評估)",
     "TWGCB(IPv6 替代措施)")

# ── 8. 主機防火牆 ──────────────────────────────────────────────
_add("fw-host", BOTH, "8. 主機防火牆",
     "主機防火牆啟用(deb:UFW;rpm:firewalld;DS Agent → 人工/替代措施)",
     "TWGCB / CIS 4(防火牆)")

# ── 9. 日誌與稽核 ──────────────────────────────────────────────
_C = "9. 日誌與稽核"
_add("log-journald", BOTH, _C, "systemd-journald 運行中", "TWGCB / CIS 6.2(日誌)")
_add("log-rsyslog", BOTH, _C, "rsyslog 運行中(僅 journald → 注意)",
     "TWGCB / CIS 6.2")
_add("log-auditd", BOTH, _C,
     "auditd 運行中(auditbeat 接管 → 人工/EDR 替代措施)", "TWGCB / CIS 6.3(auditd)")
_add("log-audit-rules", BOTH, _C, "audit 規則已載入(>1 條)", "TWGCB / CIS 6.3")
_add("log-remote", BOTH, _C,
     "rsyslog 遠端轉送已設定(SIEM/EDR 集中收集可列替代)", "TWGCB / CIS 6.2")

# ── 10. SSH 伺服器 ─────────────────────────────────────────────
_C = "10. SSH 伺服器(sshd 有效組態)"
for _id, _d, _r in (
    ("ssh-root", "禁止 root 直接登入(PermitRootLogin no)", "CIS 5.1.20"),
    ("ssh-maxauth", "登入嘗試次數上限(MaxAuthTries ≤ 4)", "CIS 5.1.16"),
    ("ssh-rhosts", "忽略 rhosts(IgnoreRhosts yes)", "CIS U22 5.1.11 / R9 5.1.13"),
    ("ssh-hostbased", "禁用主機信任認證(HostbasedAuthentication no)", "CIS U22 5.1.10 / R9 5.1.12"),
    ("ssh-emptypw", "禁止空密碼(PermitEmptyPasswords no)", "CIS 5.1.19"),
    ("ssh-x11", "停用 X11 轉送(X11Forwarding no)", "CIS U22 5.1.8 / R9 5.1.10(DisableForwarding)"),
    ("ssh-alive", "閒置逾時(ClientAliveInterval 1~900;0 = 永不逾時視為不符)",
     "CIS U22 5.1.7 / R9 5.1.9 / STIG 600"),
    ("ssh-alivecount", "ClientAliveCountMax 1~3(與 Interval 併用才會真正斷線)",
     "CIS U22 5.1.7 / R9 5.1.9"),
    ("ssh-grace", "LoginGraceTime 1~60 秒(0 = 無限寬限視為不符)", "CIS U22 5.1.13 / R9 5.1.14"),
    ("ssh-banner", "SSH 登入橫幅指向警語檔", "TWGCB / CIS U22 5.1.5 / R9 5.1.8"),
    ("ssh-pam", "UsePAM 啟用", "CIS 5.1.22"),
    ("ssh-ciphers", "無弱加密演算法(CBC/3DES/arcfour 等)", "CIS U22 5.1.6 / R9 5.1.4"),
    ("ssh-macs", "無弱 MAC(MD5/SHA1/umac-64)", "CIS U22 5.1.15 / R9 5.1.6"),
    ("ssh-kex", "無弱金鑰交換(SHA1/group1)", "CIS U22 5.1.12 / R9 5.1.5"),
):
    _add(_id, BOTH, _C, _d, _r)

# ── 11. PAM 與密碼原則 ─────────────────────────────────────────
_C = "11. PAM 與密碼原則"
_add("pam-pwquality", BOTH, _C,
     "密碼品質模組已安裝(deb:libpam-pwquality;rpm:libpwquality)",
     "TWGCB / CIS 5.3.3.2")
_add("pam-minlen", BOTH, _C, "密碼最小長度 minlen ≥ 14", "CIS 5.3.3.2.2 / STIG 15")
for _cred in ("dcredit", "ucredit", "lcredit", "ocredit"):
    _add(f"pam-{_cred}", BOTH, _C, f"密碼複雜度 {_cred} ≤ -1(各類字元至少 1)",
         "CIS 5.3.3.2.3")
_add("pam-faillock", BOTH, _C,
     "登入失敗鎖定 pam_faillock(deb:common-auth;rpm:system-auth/faillock.conf)",
     "TWGCB / CIS 5.3.3.1")
_add("pam-history", BOTH, _C, "密碼歷史記錄 pam_pwhistory(建議 ≥3 次;未設 → 注意)",
     "TWGCB / CIS 5.3.3.3.1")
_add("pam-hash", BOTH, _C, "密碼雜湊 ENCRYPT_METHOD = SHA512 或 YESCRYPT",
     "TWGCB / CIS 5.4.1.4")

# ── 12. 使用者帳號與環境 ────────────────────────────────────────
_C = "12. 使用者帳號與環境"
_add("acct-passmax", BOTH, _C, "PASS_MAX_DAYS ≤ 90(本平台統一採 TWGCB)",
     "TWGCB ≤90(CIS 5.4.1.1:≤365)")
_add("acct-passmax-existing", BOTH, _C,
     "既有帳號密碼最長使用期限 ≤ 90 天(直接讀 /etc/shadow 第 5 欄;"
     "login.defs 僅作用於新建帳號,既有帳號需 chage -M)",
     "TWGCB ≤90(既有帳號)")
_add("acct-passmin", BOTH, _C, "PASS_MIN_DAYS ≥ 1", "TWGCB(CIS v2.0.0 世代已無本條)")
_add("acct-passwarn", BOTH, _C, "PASS_WARN_AGE ≥ 7", "TWGCB / CIS 5.4.1.3")
_add("acct-umask", BOTH, _C, "預設 UMASK = 027", "CIS 5.4.3.3 / TWGCB")
_add("acct-tmout", BOTH, _C,
     "Shell 閒置逾時 TMOUT 已設定(建議 ≤900 秒;rpm 含 /etc/bashrc)",
     "TWGCB / CIS 5.4.3.2")
_add("acct-uid0", BOTH, _C, "UID 0 帳號僅 root", "TWGCB / CIS 5.4.2.1")
_add("acct-emptypw", BOTH, _C, "無空密碼帳號(/etc/shadow)", "TWGCB / CIS 7.2.2")
_add("acct-su", BOTH, _C, "su 限制群組 pam_wheel(未設 → 注意)",
     "TWGCB / CIS 5.2.7")

# ── 13. cron / at ─────────────────────────────────────────────
_C = "13. cron / at"
_add("cron-crontab", BOTH, _C, "/etc/crontab 權限 ≤600", "TWGCB / CIS 2.4(cron)")
for _d in ("hourly", "daily", "weekly", "monthly", "d"):
    # 腳本 ID 取路徑 basename:cron-dir-cron.hourly ... cron-dir-cron.d
    _add(f"cron-dir-cron.{_d}", BOTH, _C,
         f"/etc/cron.{_d} 目錄權限 ≤700", "TWGCB / CIS 2.4")
_add("cron-allow", BOTH, _C, "/etc/cron.allow 存在(白名單制)", "TWGCB / CIS 2.4")
_add("cron-at", BOTH, _C, "/etc/at.allow 存在(未裝 at → 不適用)", "TWGCB / CIS 2.4")

# ── 14. 關鍵檔案權限 ────────────────────────────────────────────
_C = "14. 關鍵檔案權限"
_add("perm-passwd", BOTH, _C, "/etc/passwd ≤644 root:root", "TWGCB / CIS 7.1.1")
_add("perm-group", BOTH, _C, "/etc/group ≤644 root:root", "TWGCB / CIS 7.1.3")
_add("perm-shadow", BOTH, _C,
     "/etc/shadow 權限(deb:≤640 root:shadow;rpm:0000 root:root)",
     "CIS 7.1.5(兩系同號)")
_add("perm-gshadow", BOTH, _C,
     "/etc/gshadow 權限(deb:≤640 root:shadow;rpm:0000 root:root)",
     "CIS 7.1.7(兩系同號)")
_add("perm-ww", BOTH, _C, "無 world-writable 檔案(SLOW=1 全磁碟掃描)",
     "TWGCB / CIS 7.1.11")
_add("perm-unowned", BOTH, _C, "無無主檔案(SLOW=1 全磁碟掃描)",
     "TWGCB / CIS 7.1.12")
_add("perm-scan", BOTH, _C, "(未開 SLOW 時的提示項)全磁碟掃描已略過",
     "—(系統提示)")

# ── 15. GNOME GUI ─────────────────────────────────────────────
_add("gui-desktop", BOTH, "15. GNOME GUI 項目",
     "無桌面環境(Server)→ GUI 章節整章不適用;偵測到 → 注意",
     "TWGCB / CIS U22 1.7 / R9 1.8(GNOME)")


# ══════════════════════════════════════════════════════════════
# FortiGate(drivers/fortigate.py;CIS FortiGate 7.4.x v1.0.1,
# 條次依 CIS 7.4.x v1.0.1 核實;交叉參照 DISA FortiGate NDM STIG V1R5。
# 範圍:僅系統管理面強化,policy 內容類(CIS 第 3/4 章)依平台定位不納)
# ══════════════════════════════════════════════════════════════
FGT = ("fortigate",)

_C = "1. 基礎設定"
_add("fgt-dns", FGT, _C, "DNS 伺服器已設定", "CIS 1.1")
_add("fgt-wan-mgmt", FGT, _C,
     "WAN 介面未開放管理服務(https/ssh/ping/http/telnet/snmp 等)", "CIS 1.3 / STIG FGFW-ND-000200(部分)")

_C = "2. 系統管理強化"
_add("fgt-prelogin-banner", FGT, _C, "登入前警語 pre-login-banner 啟用", "CIS 2.1.1 / STIG FGFW-ND-000050,000055")
_add("fgt-postlogin-banner", FGT, _C, "登入後警語 post-login-banner 啟用", "CIS 2.1.2")
_add("fgt-timezone", FGT, _C, "時區已正確設定", "CIS 2.1.3 / STIG FGFW-ND-000125")
_add("fgt-ntp", FGT, _C, "NTP 時間同步啟用(ntpsync)", "CIS 2.1.4 / STIG FGFW-ND-000120,000215")
_add("fgt-hostname", FGT, _C, "主機名稱已設定且非預設名", "CIS 2.1.5")
_add("fgt-tls-version", FGT, _C,
     "管理 GUI 僅用 TLS 1.3(含 1.2 列注意;有弱版本不符)", "CIS 2.1.10 / STIG FGFW-ND-000205")
_add("fgt-pwd-policy", FGT, _C,
     "密碼原則啟用、最小長度 ≥14 且套用於管理密碼", "CIS 2.2.1 / STIG FGFW-ND-000220(STIG 15)")
_add("fgt-lockout", FGT, _C,
     "登入失敗鎖定(threshold ≤3、duration 60–900 秒)", "CIS 2.2.2 / STIG FGFW-ND-000045(STIG 900/3)")
_add("fgt-admin-default", FGT, _C,
     "預設 admin 帳號處置(存在時人工確認密碼已變更)", "CIS 2.4.1 / STIG FGFW-ND-000250,000030")
_add("fgt-trusthost", FGT, _C,
     "全部管理帳號皆設 trusted host", "CIS 2.4.2")
_add("fgt-idle-timeout", FGT, _C,
     "管理閒置逾時 admintimeout ≤5 分(6–15 列注意)", "CIS 2.4.4 / STIG FGFW-ND-000270,000275(CAT I)")
_add("fgt-encrypted-mgmt", FGT, _C,
     "全部介面僅加密管理通道(無 http/telnet allowaccess)", "CIS 2.4.5 / STIG FGFW-ND-000260,000265(CAT I)")
_add("fgt-admin-telnet", FGT, _C, "Telnet 管理停用(admin-telnet)",
     "CIS 2.4.5 補強 / STIG FGFW-ND-000265")
_add("fgt-admin-ports", FGT, _C,
     "管理埠改離預設(sport≠443、port≠80)且 https-redirect 停用", "CIS 2.4.7")
_add("fgt-strong-crypto", FGT, _C, "強加密 strong-crypto 啟用",
     "CIS 2.1.9")
_add("fgt-ssl-static-keys", FGT, _C,
     "TLS 靜態金鑰加密套件停用(ssl-static-key-ciphers)", "CIS 2.1.8")
_add("fgt-gui-hostname", FGT, _C,
     "登入頁不顯示主機名稱(gui-display-hostname)", "CIS 2.1.13")
_add("fgt-cpu-log", FGT, _C,
     "單核 CPU 過載事件記錄啟用(log-single-cpu-high)", "CIS 2.1.12")

_C = "3. SNMP"
_add("fgt-snmp-v1v2c", FGT, _C,
     "SNMP v1/v2c 停用(無 community;僅 v3 或整體停用)", "CIS 2.3.1 / STIG FGFW-ND-000210")

_C = "4. 日誌與更新"
_add("fgt-syslog", FGT, _C,
     "遠端 syslog 集中日誌啟用(僅 FortiAnalyzer 列注意)", "CIS 7.2.1 / STIG FGFW-ND-000110,000295")
_add("fgt-event-logging", FGT, _C,
     "事件日誌啟用(log eventfilter event)", "CIS 7.1.1 / STIG FGFW-ND-000005(事件稽核群)")
_add("fgt-faz-encryption", FGT, _C,
     "FortiAnalyzer 傳輸加密(reliable + enc-algorithm high;未用不適用)",
     "CIS 7.3.1")
_add("fgt-usb-autoinstall", FGT, _C,
     "USB 自動安裝停用(auto-install config/image)", "CIS 2.1.7")


# ══════════════════════════════════════════════════════════════
# PaloAlto PAN-OS(drivers/paloalto.py;CIS Palo Alto Firewall 11
# Benchmark v1.2.0,條次已逐條核對原文,見 sample/cis-compare-paloalto.md;
# DISA PAN-OS NDM STIG 交叉參照。CIS 無對應條目者標「平台自訂」。
# 範圍:僅系統管理面強化,security policy/解密/zone 等內容類不納)
# ══════════════════════════════════════════════════════════════
PAN = ("paloalto",)

_C = "1. 系統管理強化"
_add("pan-hostname", PAN, _C, "主機名稱已設定", "平台自訂 / STIG PANW-NM-000029(部分)")
_add("pan-timezone", PAN, _C, "時區已設定", "平台自訂 / STIG PANW-NM-000101(STIG須UTC)")
_add("pan-login-banner", PAN, _C, "登入警語 login-banner 已設定", "CIS 1.1.2 / STIG PANW-NM-000016")
_add("pan-permitted-ip", PAN, _C,
     "管理介面限制來源 IP(permitted-ip;含 0.0.0.0/0 視同未限制)",
     "CIS 1.2.1")
_add("pan-disable-telnet", PAN, _C, "Telnet 管理停用(disable-telnet)", "CIS 1.2.3 / STIG PANW-NM-000061,000117")
_add("pan-disable-http", PAN, _C, "HTTP 明文管理停用(disable-http)", "CIS 1.2.3 / STIG PANW-NM-000061,000117")
_add("pan-ntp", PAN, _C, "NTP 主+次雙伺服器已設定(僅一台列注意)", "CIS 1.6.2 / STIG PANW-NM-000098,000099,000100")
_add("pan-ntp-auth", PAN, _C, "NTP 啟用認證(none/MD5 列注意)",
     "CIS 1.6.2 Rationale / STIG PANW-NM-000145")
_add("pan-update-verify", PAN, _C,
     "更新伺服器憑證驗證 server-verification 啟用", "CIS 1.6.1")
_add("pan-idle-timeout", PAN, _C,
     "管理閒置逾時 idle-timeout 1–10 分(0=永不登出、未設=預設 60 皆不符)",
     "CIS 1.4.1 / STIG PANW-NM-000069(CAT I)")
_add("pan-log-high-dp", PAN, _C,
     "高資料面負載事件記錄 enable-log-high-dp-load 啟用", "CIS 1.1.3 / STIG PANW-NM-000144")
_add("pan-lockout", PAN, _C,
     "登入失敗鎖定 failed-attempts 非零(lockout-time=0 列注意)", "CIS 1.4.2 / STIG PANW-NM-000015,000092")

_C = "2. 密碼原則"
_add("pan-pwd-complexity", PAN, _C, "密碼複雜度已啟用", "CIS 1.3.1")
_add("pan-pwd-minlen", PAN, _C, "密碼最小長度 ≥12", "CIS 1.3.2 / STIG PANW-NM-000053(STIG 15)")
_add("pan-pwd-uppercase", PAN, _C, "密碼須含大寫字母 ≥1", "CIS 1.3.3 / STIG PANW-NM-000055")
_add("pan-pwd-lowercase", PAN, _C, "密碼須含小寫字母 ≥1", "CIS 1.3.4 / STIG PANW-NM-000056")
_add("pan-pwd-numeric", PAN, _C, "密碼須含數字 ≥1", "CIS 1.3.5 / STIG PANW-NM-000057")
_add("pan-pwd-special", PAN, _C, "密碼須含特殊字元 ≥1", "CIS 1.3.6 / STIG PANW-NM-000058")
_add("pan-pwd-expiry", PAN, _C,
     "密碼有效期 1–90 天(0/未設=永不到期不符)", "CIS 1.3.7")
_add("pan-pwd-differs", PAN, _C, "新舊密碼相異字元數 ≥3", "CIS 1.3.8 / STIG PANW-NM-000059(STIG ≥8)")
_add("pan-pwd-history", PAN, _C, "密碼重用限制 ≥24 代", "CIS 1.3.9")
_add("pan-pwd-profiles", PAN, _C,
     "無個別密碼 Profile(存在時列注意請人工比對)", "CIS 1.3.10 / STIG PANW-NM-000142")

_C = "3. 管理帳號"
_add("pan-superuser", PAN, _C, "superuser 帳號最小化(>2 列注意)", "平台自訂(近似 STIG PANW-NM-000048)")
_add("pan-admin-default", PAN, _C,
     "預設 admin 帳號處置(存在時人工確認密碼已變更)", "平台自訂 / STIG PANW-NM-000143(CAT I)")

_C = "4. SNMP"
_add("pan-snmp-v2c", PAN, _C,
     "SNMP 僅用 V3(未設 access-setting 時預設 V2c,列人工)",
     "CIS 1.5.1 / STIG PANW-NM-000118(CAT I)")

_C = "5. 日誌"
_add("pan-log-forward", PAN, _C,
     "syslog 日誌轉送已設定", "CIS 1.1.1.1 / STIG PANW-NM-000128,000024")


# ══════════════════════════════════════════════════════════════
# F5 BIG-IP(drivers/f5.py;DISA F5 BIG-IP TMOS STIG Y25M07 /
# Device Management (NDM) STIG V1R2、CIS F5 Networks v1.0.0(ARCHIVE 2021,
# 條次已逐條核對原文,見 sample/cis-compare-f5.md;hostname/timezone
# 在 CIS 無對應條目,標平台自訂)。
# 範圍:僅系統管理面強化;LTM/ASM 的 VS/policy/WAF 政策內容不納)
# ══════════════════════════════════════════════════════════════
F5 = ("f5",)

_C = "1. 管理介面強化"
_add("f5-gui-banner", F5, _C,
     "GUI 登入警語啟用且已設文字(空文字列注意)", "CIS 4.1 / STIG F5BI-DM-300014")
_add("f5-console-timeout", F5, _C,
     "Console 閒置逾時 1–600 秒(0=停用不符)", "CIS 4.4 / STIG F5BI-DM-300057(CAT I,STIG≤300)")
_add("f5-sshd-banner", F5, _C,
     "SSH 登入警語啟用且已設文字(空文字列注意)", "CIS 4.1 / STIG F5BI-DM-300098")
_add("f5-sshd-timeout", F5, _C,
     "SSH 閒置逾時 1–600 秒(0=停用不符)", "CIS 4.2 / STIG F5BI-DM-300057(CAT I,STIG≤300)")
_add("f5-ssh-algos", F5, _C,
     "SSH 演算法無弱項(arcfour/CBC/3DES/MD5 等;未明確設定列注意)",
     "CIS 4.5–4.7(現行標準)")
_add("f5-tmsh-timeout", F5, _C, "tmsh CLI 閒置逾時 1–10 分", "CIS 4.3 / STIG F5BI-DM-300057(STIG=5)")
_add("f5-sshd-allow", F5, _C,
     "SSH 管理來源限制(allow 非 ALL)", "CIS 4.8")
_add("f5-httpd-allow", F5, _C,
     "GUI 管理來源限制(allow 非 All)", "CIS 3.3")
_add("f5-gui-timeout", F5, _C, "GUI 閒置逾時 authPamIdleTimeout ≤600 秒",
     "CIS 3.1 / STIG F5BI-DM-300057(CAT I,STIG≤300)")
_add("f5-tls-version", F5, _C,
     "管理 GUI 排除弱 TLS(SSLv2/SSLv3/TLSv1/TLSv1.1)", "CIS 3.2")

_C = "2. 系統設定"
_add("f5-hostname", F5, _C, "主機名稱已設定", "平台自訂")
_add("f5-ntp", F5, _C, "NTP 冗餘雙台已設定(僅一台列注意)", "CIS 5.1")
_add("f5-timezone", F5, _C, "時區已設定", "平台自訂 / STIG F5BI-DM-300037(STIG須UTC)")

_C = "3. 密碼與帳號"
_add("f5-pwd-policy", F5, _C, "密碼原則強制 policyEnforcement 啟用",
     "CIS 1.1.3")
_add("f5-pwd-minlen", F5, _C, "密碼最小長度 ≥12(STIG 建議 15)",
     "CIS 1.1.3 / STIG F5BI-DM-300049(STIG 15)")
_add("f5-pwd-maxage", F5, _C, "密碼最長使用期 1–180 天", "CIS 1.1.3")
_add("f5-pwd-memory", F5, _C, "密碼記憶(不可重用)≥24 代", "CIS 1.1.3")
_add("f5-pwd-warning", F5, _C, "密碼到期前警告 ≥14 天", "CIS 1.1.3")
_add("f5-pwd-complexity", F5, _C,
     "密碼複雜度四類字元皆 ≥1(不足即不符)", "CIS 1.1.3 / STIG F5BI-DM-300050~300053")
_add("f5-login-failures", F5, _C, "登入失敗鎖定 maxLoginFailures 1–3",
     "CIS 1.1.3 / STIG F5BI-DM-300013(STIG=3,鎖900)")
_add("f5-admin-default", F5, _C,
     "預設 admin 帳號處置(存在時人工確認密碼已變更)", "CIS 1.1.2")
_add("f5-remote-role", F5, _C,
     "外部使用者預設角色 No Access(未用遠端認證不適用)", "CIS 2.4")
_add("f5-remote-partition", F5, _C,
     "外部使用者 Partition 存取非 All(未用遠端認證不適用)", "CIS 2.5")
_add("f5-remote-console", F5, _C,
     "外部使用者終端存取停用(未用遠端認證不適用)", "CIS 2.6")

_C = "4. SNMP"
_add("f5-snmp-v1v2c", F5, _C,
     "SNMP v1/v2c community 停用(REST 不可讀時列人工)", "CIS 6.2")

_C = "5. 日誌"
_add("f5-syslog-remote", F5, _C,
     "遠端 syslog 已設定(其他集中收集機制可列替代)", "CIS 6.5 / STIG F5BI-DM-300034(CAT I,STIG≥2)")


# ══════════════════════════════════════════════════════════════
# Citrix NetScaler / ADC(drivers/netscaler.py;出處 SDG = Citrix
# NetScaler Secure Deployment Guide(廠商官方強化指南,等同 F5/NetApp 的
# 原廠強化指南地位;https://docs.netscaler.com/en-us/netscaler-adc-secure-deployment.html)
# + 通用 NDM SRG。DISA 另有 Citrix ADC NDM STIG,但本專案未納入該文件。
# 註(2026-08-24 查證 cisecurity.org):CIS 並無 NetScaler / Citrix ADC
# Benchmark(Network Devices 類別無 Citrix),故不引 CIS、不虛構條次。
# 範圍:僅管理面強化)
# ══════════════════════════════════════════════════════════════
NS = ("netscaler",)

_C = "1. 管理介面存取"
_add("ns-nsip-telnet", NS, _C, "NSIP Telnet 管理停用", "Citrix SDG / SRG")
_add("ns-nsip-ftp", NS, _C, "NSIP FTP 管理停用", "Citrix SDG / SRG")
_add("ns-nsip-gui", NS, _C, "NSIP GUI 僅 HTTPS(SECUREONLY)", "Citrix SDG")
_add("ns-nsip-restrict", NS, _C,
     "NSIP restrictaccess 啟用(只允許啟用的管理服務)", "Citrix SDG")

_C = "2. 系統參數"
_add("ns-timeout", NS, _C, "管理 session 逾時 timeout 設定且 ≤900 秒", "Citrix SDG")
_add("ns-strong-password", NS, _C, "強密碼原則 strongpassword 啟用", "Citrix SDG")
_add("ns-min-password", NS, _C, "密碼最小長度 minpasswordlen ≥8", "Citrix SDG / STIG")

_C = "3. SSL 管理"
_add("ns-ssl-reneg", NS, _C, "SSL 重新協商 denysslreneg 限制(NONSECURE/ALL)",
     "Citrix SDG")

_C = "4. 時間同步"
_add("ns-ntp", NS, _C, "NTP 伺服器已設定", "Citrix SDG / SRG")

_C = "5. SNMP"
_add("ns-snmp-community", NS, _C, "SNMP v1/v2c community 停用(改用 v3)",
     "Citrix SDG / STIG")

_C = "6. 日誌"
_add("ns-syslog", NS, _C, "遠端 syslog action 已設定", "Citrix SDG / SRG")

_C = "7. 管理帳號"
_add("ns-default-nsroot", NS, _C,
     "預設 nsroot 帳號處置(存在時人工確認密碼已變更)", "Citrix SDG")


# ══════════════════════════════════════════════════════════════
# VMware vCenter(VCSA)(drivers/vcenter.py;DISA vSphere 8.0 vCenter
# STIG / VCSA Management。範圍:appliance 管理面強化;ESXi/VM/權限指派不納)
# 註:CIS VMware ESXi 8.0 Benchmark v1.3.0 §Intended Audience 明文排除
# vCenter,全文無 VCSA 條目,故本組不引 CIS(比對見 sample/cis-compare-vcenter.md);
# 其 §3.15 對密碼最長天數的立場(建議 99999,不強制定期換密)與 STIG ≤90 相反。
# ══════════════════════════════════════════════════════════════
VC = ("vcenter",)

_C = "1. 時間同步"
_add("vc-ntp", VC, _C, "NTP 伺服器已設定", "STIG VCSA-80-000158")
_add("vc-timesync", VC, _C, "時間同步模式為 NTP(非 HOST/DISABLED)", "STIG VCSA-80-000158")

_C = "2. 管理存取"
_add("vc-ssh", VC, _C, "SSH 存取停用(非必要時)", "STIG VCSA-80-000303")
_add("vc-shell", VC, _C, "Bash shell 存取停用", "STIG(VCSA)")
_add("vc-dcui", VC, _C, "DCUI 主控台存取(依營運需要人工評估)", "STIG(VCSA)")

_C = "3. 日誌"
_add("vc-syslog", VC, _C, "遠端日誌轉送已設定", "STIG VCSA-80-000148")

_C = "4. 帳號密碼原則"
_add("vc-pwd-maxage", VC, _C, "本機帳號密碼最長天數 ≤90", "STIG VCSA-80-000079(關聯;appliance OS 帳號非 SSO)")
_add("vc-root-expiry", VC, _C,
     "root 密碼設定過期(max_days > 0,非 -1 永不過期)", "STIG")


# ══════════════════════════════════════════════════════════════
# Cisco IOS / IOS-XE(drivers/cisco.py;CIS Cisco IOS XE 17.x Benchmark
# v2.2.1,條次已逐條核對原文,見 sample/cis-compare-cisco.md;
# DISA Cisco IOS Switch NDM STIG 交叉參照。範圍:管理面強化)
# ══════════════════════════════════════════════════════════════
CSCO = ("cisco",)

_C = "1. 管理服務"
_add("cisco-web-mgmt", CSCO, _C,
     "Web 管理關閉或受 access-class 限制(no ip http server/secure-server)",
     "STIG CISC-ND-000470(CAT I) / CIS 1.2.9")
_add("cisco-vty-ssh", CSCO, _C, "所有 VTY 僅允許 SSH(transport input ssh)",
     "CIS 1.2.2 / STIG CISC-ND-001210(間接)")
_add("cisco-vty-acl", CSCO, _C,
     "所有 VTY 皆設 access-class 來源限制", "CIS 1.2.5 / STIG CISC-ND-000140")

_C = "2. SSH 演算法"
_add("cisco-ssh-algo", CSCO, _C,
     "SSH 伺服器演算法無弱項(無 sha1/md5/3des/cbc)",
     "STIG CISC-ND-001200,001210(CAT I)")
_add("cisco-ssh-ver", CSCO, _C,
     "明設 ip ssh version 2(未設列注意,相容模式含 v1)", "CIS 2.1.1.2 / STIG CISC-ND-001200,001210")

_C = "3. 密碼保護"
_add("cisco-pwd-encryption", CSCO, _C, "service password-encryption 啟用",
     "CIS 1.4.2 / STIG CISC-ND-000620(CAT I)")
_add("cisco-enable-secret", CSCO, _C,
     "使用 enable secret(強雜湊)非 enable password", "CIS 1.4.1 / STIG CISC-ND-000620(CAT I)")
_add("cisco-user-secret", CSCO, _C,
     "本機帳號一律 username secret(無本機帳號不適用)", "CIS 1.4.3 / STIG CISC-ND-000620(關聯)")

_C = "4. SNMP"
_add("cisco-snmp-community", CSCO, _C, "SNMP v1/v2c community 停用(改用 v3)",
     "CIS 1.5.1–1.5.3 / STIG CISC-ND-001130,001140(平台較嚴)")

_C = "5. 時間與日誌"
_add("cisco-ntp", CSCO, _C, "NTP 伺服器至少兩台(僅一台列注意)",
     "CIS 2.3.2 / STIG CISC-ND-001030")
_add("cisco-ntp-auth", CSCO, _C,
     "NTP 認證(authenticate/authentication-key/trusted-key;未用 NTP 不適用)",
     "CIS 2.3.1.1–2.3.1.3 / STIG CISC-ND-001150")
_add("cisco-logging", CSCO, _C, "遠端 syslog 已設定", "CIS 2.2.4 / STIG CISC-ND-001450(CAT I,STIG需2台)")
_add("cisco-timestamps", CSCO, _C,
     "debug 訊息含時間戳(service timestamps debug datetime)", "CIS 2.2.6 / STIG CISC-ND-000280(STIG:log datetime)")
_add("cisco-login-log", CSCO, _C,
     "登入成功/失敗皆記錄(login on-success/on-failure log)", "CIS 2.2.8 / STIG CISC-ND-001260")

_C = "6. AAA / 橫幅 / 逾時"
_add("cisco-aaa", CSCO, _C, "aaa new-model 啟用", "CIS 1.1.1")
_add("cisco-aaa-auth-login", CSCO, _C,
     "aaa authentication login 已設定", "CIS 1.1.2 / STIG CISC-ND-000490(關聯)")
_add("cisco-banner", CSCO, _C, "登入橫幅 banner 已設定",
     "CIS 1.3.1–1.3.3 / STIG CISC-ND-000160")
_add("cisco-exec-timeout", CSCO, _C,
     "line exec-timeout ≤10 分且非 0(未明設=IOS 預設 10 分,符合)",
     "CIS 1.2.6–1.2.8 / STIG CISC-ND-000720(CAT I,STIG≤5分)")


# ══════════════════════════════════════════════════════════════
# NetApp ONTAP(drivers/netapp.py;ONTAP 9 Security Hardening Guide
# TR-4569 + 通用儲存/NDM SRG。範圍:cluster 管理面強化)
# ══════════════════════════════════════════════════════════════
NTAP = ("netapp",)

_C = "1. 時間"
_add("netapp-ntp", NTAP, _C, "NTP 伺服器已設定", "TR-4569 / STIG NAOT-AU-000004(V-246936)")
_add("netapp-timezone", NTAP, _C, "時區已設定", "TR-4569 / STIG NAOT-AU-000006(V-246938)")

_C = "2. SSH 演算法"
_add("netapp-ssh-ciphers", NTAP, _C, "SSH 加密無弱演算法(無 cbc/3des)", "TR-4569")
_add("netapp-ssh-macs", NTAP, _C, "SSH MAC 無弱演算法(無 umac-64/md5/sha1)", "TR-4569")

_C = "3. SNMP"
_add("netapp-snmp-v1v2c", NTAP, _C, "SNMP v1/v2c community 停用(改用 v3)",
     "STIG NAOT-IA-000003(V-246949) / TR-4569")

_C = "4. 稽核與日誌"
_add("netapp-audit", NTAP, _C, "管理命令稽核啟用(cli/ontapi/http)", "TR-4569")
_add("netapp-audit-dest", NTAP, _C, "稽核遠端轉送已設定", "STIG NAOT-SI-000001(V-246964,CAT I) / TR-4569")

_C = "5. 橫幅與帳號"
_add("netapp-banner", NTAP, _C, "登入橫幅/訊息已設定", "STIG NAOT-AC-000011(V-246932) / TR-4569")
_add("netapp-admin-default", NTAP, _C,
     "預設 admin 帳號處置(存在時人工確認密碼已變更)", "TR-4569")


# ══════════════════════════════════════════════════════════════
# Aruba Mobility Controller AOS 8(drivers/aruba.py;Aruba AOS8
# Hardening / Security Best Practices + 通用 NDM SRG。範圍:管理面強化)
# ══════════════════════════════════════════════════════════════
ARU = ("aruba",)

_C = "1. 管理服務"
_add("aruba-telnet", ARU, _C, "Telnet CLI 停用", "Aruba Hardening / SRG")
_add("aruba-ssh-dsa", ARU, _C, "SSH DSA 主機金鑰停用(弱)", "Aruba Hardening")
_add("aruba-ssh-ciphers", ARU, _C, "SSH 加密無弱演算法(無 cbc/3des)",
     "Aruba Hardening / SRG")

_C = "2. SNMP"
_add("aruba-snmp-v1v2c", ARU, _C, "SNMP v1/v2c community 停用(改用 v3)",
     "Aruba Hardening / SRG")
_add("aruba-snmp-default", ARU, _C, "無預設 community 名稱(public/private)",
     "Aruba Hardening")

_C = "3. 時間與橫幅"
_add("aruba-ntp", ARU, _C, "NTP 伺服器已設定", "SRG / STIG ARBA-ND-000298(STIG≥2)")
_add("aruba-banner", ARU, _C, "登入橫幅已設定", "SRG / STIG ARBA-ND-000215")

_C = "4. 密碼原則"
_add("aruba-pwd-policy", ARU, _C, "密碼原則啟用(Enable password policy)",
     "Aruba Hardening / SRG")
_add("aruba-pwd-minlen", ARU, _C, "密碼最小長度 ≥8", "SRG / STIG ARBA-ND-000252(STIG 15)")

_C = "5. 管理帳號"
_add("aruba-admin-default", ARU, _C,
     "預設 admin 帳號處置(存在時人工確認密碼已變更)", "Aruba Hardening / STIG ARBA-ND-000346")


# ══════════════════════════════════════════════════════════════
# FortiAuthenticator(drivers/fortiauth.py;SSH CLI show full-configuration。
# FAC Admin Guide / FortiOS 通用強化 + NDM SRG。範圍限 CLI 可得項;
# SNMP/NTP/密碼原則為 GUI-only,不在範圍)
# ══════════════════════════════════════════════════════════════
FAC = ("fortiauth",)

_C = "1. 管理介面存取"
_add("fac-mgmt-access", FAC, _C,
     "管理介面僅加密服務(allowaccess 無 telnet/http)", "SRG / FortiOS")
_add("fac-allowed-hosts", FAC, _C,
     "管理來源限制 allowed-hosts 已設定", "SRG")

_C = "2. 帳號"
_add("fac-admin-maintainer", FAC, _C,
     "維護帳號 admin-maintainer 停用(主控台可重設密碼)", "FAC Admin Guide")

_C = "3. 系統"
_add("fac-dns", FAC, _C, "DNS 已設定", "FortiOS 通用")
_add("fac-timezone", FAC, _C, "時區已設定", "FortiOS 通用")


def items_for(family: str) -> list[dict]:
    """指定系列(deb/rpm)適用的檢查項清單(依目錄順序)。"""
    return [it for it in CATALOG if family in it["fams"]]


def valid_ids(family: str) -> set[str]:
    return {it["id"] for it in items_for(family)}

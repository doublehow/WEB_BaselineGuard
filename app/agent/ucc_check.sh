#!/bin/bash
#===============================================================================
# ucc_check.sh — Linux GCB/CIS 組態檢查腳本【純檢查:只稽核、零改動】
# BaselineGuard 平台配套版(SCRIPT_VERSION 見下)
#
# 支援發行版(自動偵測 /etc/os-release):
#   - Ubuntu / Debian(deb):TWGCB-01-014《Ubuntu 22.04 LTS 政府組態基準》
#     v1.2、CIS Ubuntu 22.04 v2.0.0 / 24.04 v1.0.0
#   - RHEL / Rocky / AlmaLinux(rpm):CIS RHEL 9 Benchmark v2.0.0
#     (交叉參照 RHEL 8;/etc/shadow 0000 root:root 依 CIS §7.1.5)
#   兩系共用穩定檢查項 ID,發行版特有項目(AppArmor/SELinux、APT/DNF 簽章)
#   各有專屬 ID。本腳本為「檢查模式」:不修改任何設定。
#
# v2.2.1 變更(僅描述文字,判定邏輯零改動):
#   - SSH 檢查項描述內嵌的 CIS 條次改依 CIS Ubuntu 22.04 v2.0.0 / RHEL 9
#     v2.0.0 原文核對(兩系編號不同者標 U22/R9 雙條次;X11 對應 v2.0.0 的
#     DisableForwarding),與 check_items.py 目錄同步。
# v2.2.0 變更(假陰性修正:凡「看似符合實則不符」的判斷邏輯一律收緊):
#   - 權限比較改用八進位位元遮罩 perm_ok()(原本 stat %a 字串走十進位比較,
#     /etc/passwd 606、shadow 604、grub.cfg 444、cron.d 550 都會被誤判為符合)
#   - 所有數值比較先經 is_num()/is_int() 純數字驗證(非數值會被 bash 當變數名解析成 0)
#   - SSH:ClientAliveInterval / LoginGraceTime 改為「1 ≤ 值 ≤ 上限」(0 = 永不逾時);
#     新增 ssh-alivecount(ClientAliveCountMax);sshd -T 失敗時 14 項逐一輸出人工
#     (移除目錄外的 ssh-config ID)
#   - modprobe 停用改判 install + blacklist 兩條件並存,排除註解行並加字界
#   - sysctl 改同時查執行值與 /etc/sysctl.conf、sysctl.d 持久化值(僅執行值符合 → 注意)
#   - APT 簽章加驗 deb822 .sources 的 Trusted: yes;DNF 未顯式 gpgcheck=1 → 注意
#   - AppArmor enforce=0 不再無條件符合;faillock 須掛載於 PAM stack 並檢查 deny/unlock_time
#   - UMASK 改「027 或更嚴格」位元判斷;pwquality 接受 minclass≥4 等價替代
#   - TMOUT 檢查實際數值並支援 export 寫法;新增 acct-passmax-existing(既有帳號密碼期限)
#   - nfs-server 同時查 is-enabled 與 is-active;auditd 規則改判輸出內容而非行數
#   - SLOW 掃描改逐一走訪本機實體掛載點(原 find / -xdev 漏掉 /var、/home 等獨立掛載)
#   - 條件不成立的項目改輸出「不適用/人工」而非靜默消失(grub/cron/ntp-src/audit-rules 等)
#   - json_escape 處理其餘控制字元(U+0000–U+001F),避免產生非法 JSON
# v2.1.1:JSON 輸出新增 "family" 欄位(deb/rpm),供平台按系列套用檢查項啟用設定
# v2.1 變更:
#   - 新增 RHEL/Rocky 支援:rpm 套件查詢、SELinux(取代 AppArmor)、
#     firewalld(取代 UFW)、dnf-automatic(取代 unattended-upgrades)、
#     gpgcheck、grub2/user.cfg、system-auth/faillock.conf、chronyd、
#     shadow/gshadow 權限採 0000 root:root(CIS RHEL)
#   - pwquality 改同時讀 pwquality.conf 與 pwquality.conf.d/*.conf
# v2.0 變更(平台化):
#   - 每個檢查項賦予穩定 ID;UCC_JSON_OUT=<路徑> 輸出機器可讀 JSON;
#     非互動模式自動偵測 root / 免密 sudo;顏色僅互動終端啟用
#
# 使用方式:
#   bash ucc_check.sh                            # 快速檢查(略過全磁碟慢速掃描)
#   SLOW=1 bash ucc_check.sh                     # 含 world-writable/無主檔案掃描
#   UCC_JSON_OUT=/tmp/ucc.json bash ucc_check.sh # 另輸出 JSON(平台模式)
#
# 結果標示:
#   [符合] [不符] [注意] [人工](本環境有替代措施,列例外評估)[不適用]
#===============================================================================
set -u

SCRIPT_VERSION="2.2.1"
STARTED_AT=$(date -Is)

#---------------------------------------
# 發行版偵測:deb(Ubuntu/Debian)/ rpm(RHEL/Rocky/Alma)
#---------------------------------------
OS_PRETTY=$(. /etc/os-release; echo "$PRETTY_NAME")
_os_ids=$(. /etc/os-release; echo "$ID ${ID_LIKE:-}")
FAMILY=""
case " $_os_ids " in
  *" ubuntu "*|*" debian "*) FAMILY="deb" ;;
  *" rhel "*|*" rocky "*|*" almalinux "*|*" centos "*|*" fedora "*) FAMILY="rpm" ;;
esac
if [[ -z "$FAMILY" ]]; then
  echo "不支援的發行版:$OS_PRETTY(僅支援 Ubuntu/Debian 與 RHEL/Rocky/Alma 系)"
  exit 1
fi

# 套件已安裝?(依家族選 dpkg / rpm)
pkg_ok() {
  if [[ "$FAMILY" == "deb" ]]; then dpkg -s "$1" &>/dev/null
  else rpm -q "$1" &>/dev/null; fi
}

#---------------------------------------
# 顏色:互動終端才上色(JSON/管線模式維持純文字,回傳報告乾淨)
#---------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  CN=$'\033[0m'; CC=$'\033[1;36m'; CG=$'\033[1;32m'; CR=$'\033[1;31m'
  CY=$'\033[1;33m'; CM=$'\033[1;35m'; CW=$'\033[0;37m'
else
  CN=""; CC=""; CG=""; CR=""; CY=""; CM=""; CW=""
fi

#---------------------------------------
# 權限:root 直跑;非 root 互動要求 sudo;非互動(平台代跑)需 root 或免密 sudo
#---------------------------------------
if [[ $EUID -eq 0 ]]; then
  SUDO=""
elif [[ -n "${UCC_JSON_OUT:-}" ]]; then
  if sudo -n true 2>/dev/null; then SUDO="sudo -n"
  else echo "非互動模式需以 root 執行(或設定免密 sudo)"; exit 1; fi
else
  sudo -v || { echo "需要 sudo 權限進行唯讀檢查"; exit 1; }
  SUDO="sudo"
fi

#---------------------------------------
# 計數與輸出工具:r_* 第一參數為穩定檢查項 ID(平台彙總/比較用)
#---------------------------------------
C_PASS=0; C_FAIL=0; C_WARN=0; C_MANUAL=0; C_NA=0
FAIL_LIST=()
CUR_CAT=""
ITEMS_TMP=$(mktemp); trap 'rm -f "$ITEMS_TMP"' EXIT
US=$'\x1f'   # 欄位分隔:unit separator,不會出現在描述文字中

add_item() { printf '%s%s%s%s%s%s%s\n' "$1" "$US" "$CUR_CAT" "$US" "$2" "$US" "$3" >> "$ITEMS_TMP"; }
say_cat()  { CUR_CAT="$*"; echo -e "\n${CC}━━━ $* ━━━${CN}"; }
r_pass()   { C_PASS=$((C_PASS+1));     printf "  ${CG}[符合]${CN}   %s\n" "$2"; add_item "$1" pass "$2"; }
r_fail()   { C_FAIL=$((C_FAIL+1));     printf "  ${CR}[不符]${CN}   %s\n" "$2"; FAIL_LIST+=("$2"); add_item "$1" fail "$2"; }
r_warn()   { C_WARN=$((C_WARN+1));     printf "  ${CY}[注意]${CN}   %s\n" "$2"; add_item "$1" warn "$2"; }
r_manual() { C_MANUAL=$((C_MANUAL+1)); printf "  ${CM}[人工]${CN}   %s\n" "$2"; add_item "$1" manual "$2"; }
r_na()     { C_NA=$((C_NA+1));         printf "  ${CW}[不適用]${CN} %s\n" "$2"; add_item "$1" na "$2"; }

# 通用判斷:$1=ID $2=描述 $3...=指令(eval,退出碼 0=符合)
chk() { local id="$1" d="$2"; shift 2; if eval "$@" &>/dev/null; then r_pass "$id" "$d"; else r_fail "$id" "$d"; fi; }

#---------------------------------------
# 判斷用共用函式
#---------------------------------------
# 純數字驗證:bash 的 [[ -le ]]/(( )) 遇到非數值會當成變數名解析為 0,
# 導致「取不到值」被誤判為符合(假陰性),故所有數值比較前一律先驗證。
is_num() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }          # 非負整數
is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }        # 含負號整數

# 權限位元比較:實際權限不得含有「上限以外」的位元(八進位逐位判斷)
# 例:606 vs 644 → 606 含 other 的寫入位元,不符;444 vs 600 → 含 group/other 讀取位元,不符
perm_ok() {
  local p="$1" maxp="$2"
  [[ "$p" =~ ^[0-7]{1,4}$ && "$maxp" =~ ^[0-7]{1,4}$ ]] || return 1
  (( (8#$p & ~8#$maxp) == 0 ))
}

# modprobe 停用判斷(CIS 1.1.1.x):要求 install <mod> /bin/(true|false) 與 blacklist <mod> 並存。
# 一律錨定行首(自然排除 "# blacklist xxx" 註解行)並加字界(避免 blacklist hfsplus 命中 hfs)。
# $1 可用 . 當萬用字元(如 usb.storage 同時涵蓋 usb-storage / usb_storage)。
MODPROBE_DIRS=(/etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d)
mod_install_ok() {
  grep -rqsE "^[[:space:]]*install[[:space:]]+$1[[:space:]]+/bin/(true|false)([[:space:]]|$)" \
    "${MODPROBE_DIRS[@]}" 2>/dev/null
}
mod_blacklist_ok() {
  grep -rqsE "^[[:space:]]*blacklist[[:space:]]+$1([[:space:]]|$)" "${MODPROBE_DIRS[@]}" 2>/dev/null
}
# 回傳 both / install / blacklist / none
mod_state() {
  local s=""
  mod_install_ok "$1" && s="install"
  if mod_blacklist_ok "$1"; then [[ -n "$s" ]] && s="both" || s="blacklist"; fi
  printf '%s' "${s:-none}"
}

# sysctl 設定檔中的持久化值(近似套用順序:/usr/lib → /run → /etc/sysctl.d → /etc/sysctl.conf,取最後一筆)
sysctl_file_val() {
  local esc="${1//./\\.}"   # 參數名的點號在 ERE 中須轉義,免得 . 變萬用字元
  grep -hsE "^[[:space:]]*${esc}[[:space:]]*=" \
    /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null \
    | tail -1 | cut -d= -f2- | tr -d '[:space:]'
}
_sysctl_val_ok() {
  local v="$1" want="$2" op="$3"
  is_int "$v" || return 1
  if [[ "$op" == "ge" ]]; then (( v >= want )); else (( v == want )); fi
}
# sysctl 檢查:執行值與設定檔持久化值都要符合
#   $1=ID $2=描述 $3=參數 $4=期望值 $5=比較(eq 預設 / ge)
#   執行值不符 → 不符;執行值符合但設定檔缺或不符 → 注意(重開機會回退);兩者皆符 → 符合
sck_sysctl() {
  local id="$1" d="$2" k="$3" want="$4" op="${5:-eq}" run file
  run=$(sysctl -n "$k" 2>/dev/null | tr -d '[:space:]')
  file=$(sysctl_file_val "$k")
  if ! _sysctl_val_ok "${run:-}" "$want" "$op"; then
    r_fail "$id" "$d(執行值 $k=${run:-無法取得})"
  elif _sysctl_val_ok "${file:-}" "$want" "$op"; then
    r_pass "$id" "$d($k=$run,設定檔已持久化)"
  else
    r_warn "$id" "$d:執行值 $k=$run 符合,但 /etc/sysctl.conf 與 /etc/sysctl.d 未設定或值不符(設定檔值=${file:-未設}),重開機後會回退"
  fi
}

echo -e "${CC} Linux GCB/CIS 組態檢查(唯讀模式)v${SCRIPT_VERSION} ${CN}"
echo    " 主機:$(hostname)   系統:$OS_PRETTY(${FAMILY} 系)"
echo    " 時間:$(date '+%F %T')   慢速掃描:${SLOW:-0}"

#===============================================================================
say_cat "1. 磁碟與檔案系統"
#===============================================================================
for m in cramfs freevxfs jffs2 hfs hfsplus udf; do
  mst=$(mod_state "$m")
  if lsmod | grep -qw "^$m"; then r_fail "fs-mod-$m" "檔案系統模組 $m 已載入(應停用)"
  elif [[ "$mst" == "both" ]]; then r_pass "fs-mod-$m" "檔案系統模組 $m 已停用(install /bin/false + blacklist)"
  elif [[ "$mst" == "install" ]]; then r_warn "fs-mod-$m" "檔案系統模組 $m 僅設 install $m /bin/false,缺 blacklist $m(CIS 要求兩者並存)"
  elif [[ "$mst" == "blacklist" ]]; then r_warn "fs-mod-$m" "檔案系統模組 $m 僅設 blacklist,缺 install $m /bin/false(CIS 要求兩者並存)"
  else r_warn "fs-mod-$m" "檔案系統模組 $m 未載入但無停用設定(建議明文停用)"; fi
done
mst=$(mod_state "squashfs")
if [[ "$mst" == "both" ]]; then r_pass "fs-mod-squashfs" "squashfs 已停用(install /bin/false + blacklist)"
elif [[ "$FAMILY" == "deb" ]]; then
  # squashfs:snap 相依,Ubuntu 上停用會壞 snapd → 標人工
  r_manual "fs-mod-squashfs" "squashfs 未完整停用(目前:$mst)——Ubuntu snapd 相依此模組,停用需先移除 snap(建議列例外)"
else
  r_warn "fs-mod-squashfs" "squashfs 未完整停用(目前:$mst;CIS L2 要求 install /bin/false + blacklist,無 snap 相依可直接停)"
fi
mst=$(mod_state "usb.storage")
if lsmod | grep -qw "^usb_storage"; then r_warn "fs-mod-usb" "usb-storage 模組已載入(實體伺服器建議停用;VM 可列例外)"
elif [[ "$mst" == "both" ]]; then r_pass "fs-mod-usb" "usb-storage 已停用(install /bin/false + blacklist)"
elif [[ "$mst" != "none" ]]; then r_warn "fs-mod-usb" "usb-storage 停用設定不完整(目前僅 $mst;CIS 要求 install /bin/false + blacklist 並存)"
else r_manual "fs-mod-usb" "usb-storage 未載入且無停用設定(VM 環境可評估列例外)"; fi

for mp in /tmp /var /var/log /var/log/audit /home; do
  if findmnt -kn "$mp" &>/dev/null; then
    opts=$(findmnt -kn -o OPTIONS "$mp")
    r_pass "mnt-$mp" "$mp 為獨立掛載(options: $opts)"
    if [[ "$mp" == "/tmp" ]]; then
      if [[ "$opts" == *noexec* ]]; then
        r_pass "mnt-tmp-noexec" "/tmp 掛載含 noexec(注意:SOP 中 ./script 直接執行會被擋,bash script 不受影響)"
      else
        r_fail "mnt-tmp-noexec" "/tmp 未設 noexec(GCB 要求 nodev,nosuid,noexec)"
      fi
    fi
  else
    r_fail "mnt-$mp" "$mp 非獨立分割(GCB 建議獨立掛載並設 nodev/nosuid/noexec)"
    if [[ "$mp" == "/tmp" ]]; then
      r_fail "mnt-tmp-noexec" "/tmp 非獨立掛載,無從套用 noexec(GCB 要求獨立掛載並設 nodev,nosuid,noexec)"
    fi
  fi
done

#===============================================================================
say_cat "2. 套件管理與完整性"
#===============================================================================
if [[ "$FAMILY" == "deb" ]]; then
  chk "pkg-unattended" "unattended-upgrades 已安裝(安全性自動更新)" "pkg_ok unattended-upgrades"
  # 簽章繞過有兩種寫法:單行 sources.list 的 [trusted=yes],以及 Ubuntu 24.04+
  # deb822 格式 .sources 的 "Trusted: yes",兩者都要查
  if grep -rqs 'trusted=yes' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
     || grep -rqsiE '^[[:space:]]*Trusted:[[:space:]]*yes' /etc/apt/sources.list.d/ 2>/dev/null; then
    r_fail "pkg-apt-sign" "APT 套件庫存在簽章驗證繞過設定(trusted=yes 或 deb822 Trusted: yes)"
  else
    r_pass "pkg-apt-sign" "APT 套件庫均含簽章驗證(無 trusted=yes / deb822 Trusted: yes 繞過)"
  fi
else
  if pkg_ok dnf-automatic; then
    systemctl is-enabled dnf-automatic.timer &>/dev/null \
      && r_pass "pkg-unattended" "dnf-automatic 已安裝且 timer 已啟用(安全性自動更新)" \
      || r_warn "pkg-unattended" "dnf-automatic 已安裝但 timer 未啟用(systemctl enable --now dnf-automatic.timer)"
  else r_fail "pkg-unattended" "dnf-automatic 未安裝(無安全性自動更新機制)"; fi
  # 顯式 gpgcheck=0 → 不符;都沒寫 → 依賴預設值,不能算符合,標注意
  if grep -rqsE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' /etc/dnf/dnf.conf /etc/yum.repos.d/ 2>/dev/null; then
    r_fail "pkg-gpgcheck" "存在 gpgcheck=0 繞過簽章驗證(/etc/dnf/dnf.conf 或 /etc/yum.repos.d)"
  elif grep -qsE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' /etc/dnf/dnf.conf 2>/dev/null; then
    r_pass "pkg-gpgcheck" "DNF/YUM 已顯式強制簽章驗證(dnf.conf gpgcheck=1 且無 gpgcheck=0)"
  else
    r_warn "pkg-gpgcheck" "無 gpgcheck=0,但 /etc/dnf/dnf.conf 亦未顯式設定 gpgcheck=1(目前依賴預設值,建議顯式設定)"
  fi
fi
if pkg_ok aide; then r_pass "pkg-aide" "AIDE 檔案完整性工具已安裝"
else r_manual "pkg-aide" "AIDE 未安裝——本環境有 DS Integrity Monitoring 可為替代措施(需於 DSM 確認模組已開)"; fi

#===============================================================================
say_cat "3. 開機與程序強化"
#===============================================================================
# GRUB 設定檔路徑依家族(RHEL 含 EFI 佈局)
g=""
for cand in /boot/grub/grub.cfg /boot/grub2/grub.cfg \
            /boot/efi/EFI/redhat/grub.cfg /boot/efi/EFI/rocky/grub.cfg \
            /boot/efi/EFI/almalinux/grub.cfg; do
  [[ -f "$cand" ]] && { g="$cand"; break; }
done
if [[ -n "$g" ]]; then
  perm=$(stat -c '%a' "$g"); own=$(stat -c '%U:%G' "$g")
  if [[ "$own" == "root:root" ]] && perm_ok "$perm" 600; then
    r_pass "boot-grub-perm" "$g 權限 $perm $own"
  else
    r_fail "boot-grub-perm" "$g 權限 $perm $own(應 root:root 且不得含 600 以外的權限位元)"
  fi
  if [[ "$FAMILY" == "deb" ]]; then
    $SUDO grep -q "^password" "$g" && r_pass "boot-grub-pass" "GRUB 已設密碼保護" || r_fail "boot-grub-pass" "GRUB 未設密碼(防單人模式繞過)"
  else
    if $SUDO grep -qs "GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null \
       || $SUDO grep -q "password_pbkdf2" "$g" 2>/dev/null; then
      r_pass "boot-grub-pass" "GRUB2 已設密碼保護(user.cfg/password_pbkdf2)"
    else r_fail "boot-grub-pass" "GRUB2 未設密碼(grub2-setpassword;防單人模式繞過)"; fi
  fi
else
  # 找不到 grub.cfg 不能靜默跳過(項目消失=看不出缺口),改標人工
  r_manual "boot-grub-perm" "找不到 grub.cfg(已查 /boot/grub、/boot/grub2、/boot/efi/EFI/{redhat,rocky,almalinux}),權限無法判定"
  r_manual "boot-grub-pass" "找不到 grub.cfg,GRUB 密碼保護無法判定"
fi
sck_sysctl "boot-aslr" "ASLR 啟用 kernel.randomize_va_space=2(CIS 1.5.1)" kernel.randomize_va_space 2
sck_sysctl "boot-suid-dump" "SUID core dump 停用(fs.suid_dumpable=0)" fs.suid_dumpable 0
if grep -rqsE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null; then
  r_pass "boot-limits-core" "limits 已限制 core dump(hard core 0)"
else r_warn "boot-limits-core" "limits 未設 hard core 0(或改由 systemd coredump 管控,請確認)"; fi
chk "boot-prelink" "prelink 未安裝" "! pkg_ok prelink"
sck_sysctl "boot-ptrace" "ptrace 範圍限制(yama.ptrace_scope≥1)" kernel.yama.ptrace_scope 1 ge

#===============================================================================
say_cat "4. 強制存取控制(AppArmor/SELinux)"
#===============================================================================
if [[ "$FAMILY" == "deb" ]]; then
  chk "aa-active" "AppArmor 服務啟用中" "systemctl is-active apparmor"
  if command -v aa-status &>/dev/null; then
    aa_out=$($SUDO aa-status 2>/dev/null || true)
    enforce=$(awk '/profiles are in enforce mode/{print $1}' <<<"$aa_out")
    complain=$(awk '/profiles are in complain mode/{print $1}' <<<"$aa_out")
    # enforce=0 代表 AppArmor 雖啟用但無任何 profile 強制生效,不能算符合
    if ! is_num "${enforce:-}"; then
      r_manual "aa-profiles" "無法自 aa-status 取得 enforce 模式 profile 數,請人工確認"
    elif (( enforce > 0 )); then
      r_pass "aa-profiles" "AppArmor profiles:enforce=$enforce、complain=${complain:-0}"
    else
      r_fail "aa-profiles" "AppArmor 已啟用但 enforce 模式 profile 為 0(等同無強制保護;complain=${complain:-0})"
    fi
    if ! is_num "${complain:-}"; then
      r_na "aa-complain" "無法自 aa-status 取得 complain 模式 profile 數,此項不適用"
    elif (( complain > 0 )); then
      r_warn "aa-complain" "有 $complain 個 profile 處於 complain 模式(GCB 要求 enforce)"
    else
      r_pass "aa-complain" "無 profile 處於 complain 模式(全數 enforce)"
    fi
  else
    r_fail "aa-profiles" "apparmor-utils 未安裝(無法檢視 profile 狀態)"
    r_na "aa-complain" "apparmor-utils 未安裝,complain 模式 profile 數無法判定"
  fi
else
  semode=$(getenforce 2>/dev/null || echo "無法取得")
  [[ "$semode" == "Enforcing" ]] && r_pass "se-mode" "SELinux 執行模式:Enforcing" \
    || r_fail "se-mode" "SELinux 執行模式:$semode(CIS 要求 Enforcing)"
  grep -qsE '^\s*SELINUX=enforcing' /etc/selinux/config \
    && r_pass "se-config" "開機設定 SELINUX=enforcing(/etc/selinux/config)" \
    || r_fail "se-config" "開機設定非 enforcing(重開機後不會強制執行)"
  grep -qsE '^\s*SELINUXTYPE=(targeted|mls)' /etc/selinux/config \
    && r_pass "se-policy" "SELinux 政策:$(grep -sE '^\s*SELINUXTYPE=' /etc/selinux/config | cut -d= -f2)" \
    || r_fail "se-policy" "SELINUXTYPE 未設 targeted/mls"
fi

#===============================================================================
say_cat "5. 警告橫幅"
#===============================================================================
for f in /etc/issue /etc/issue.net; do
  if [[ -s $f ]]; then
    grep -qsE '\\[mrsv]' "$f" && r_fail "banner-$f" "$f 含系統資訊逸出字元(\\m \\r \\s \\v 應移除)" || r_pass "banner-$f" "$f 存在且不洩露系統資訊"
  else r_fail "banner-$f" "$f 不存在或為空(應設置法律警語)"; fi
done

#===============================================================================
say_cat "6. 服務管理"
#===============================================================================
if [[ "$FAMILY" == "deb" ]]; then
  SVC_PKGS="telnetd vsftpd rsh-server xinetd avahi-daemon cups isc-dhcp-server nfs-kernel-server rpcbind"
else
  SVC_PKGS="telnet-server vsftpd rsh-server xinetd avahi cups dhcp-server rpcbind"
fi
for pkg in $SVC_PKGS; do
  chk "svc-$pkg" "非必要服務未安裝:$pkg" "! pkg_ok $pkg"
done
if [[ "$FAMILY" == "rpm" ]]; then
  # RHEL 的 nfs-utils 兼作用戶端,改檢查伺服端服務。
  # is-enabled 與 is-active 都要查:disabled 但被手動 start 起來的服務同樣是曝險面
  nfs_en=$(systemctl is-enabled nfs-server 2>/dev/null || true)
  nfs_ac=$(systemctl is-active nfs-server 2>/dev/null || true)
  if [[ "$nfs_en" == enabled* || "$nfs_ac" == "active" || "$nfs_ac" == "activating" ]]; then
    r_fail "svc-nfs-server" "NFS 伺服器服務已啟用或運行中(is-enabled=${nfs_en:-未知}、is-active=${nfs_ac:-未知})"
  else
    r_pass "svc-nfs-server" "NFS 伺服器服務未啟用且未運行(is-enabled=${nfs_en:-disabled}、is-active=${nfs_ac:-inactive})"
  fi
fi
if pkg_ok samba || pkg_ok smbd; then r_warn "svc-samba" "samba 伺服器已安裝(本環境僅需 smbclient 用戶端,請確認用途)"
else r_pass "svc-samba" "samba 伺服器未安裝(smbclient 用戶端不在此限)"; fi
if systemctl is-active systemd-timesyncd &>/dev/null || systemctl is-active chrony &>/dev/null \
   || systemctl is-active chronyd &>/dev/null; then
  r_pass "svc-timesync" "時間同步服務啟用中"
  src=$(timedatectl show-timesync -p ServerName --value 2>/dev/null || true)
  [[ -z "${src:-}" ]] && src=$(grep -hsE '^\s*(server|pool)\s' /etc/chrony/chrony.conf /etc/chrony.conf 2>/dev/null | awk '{print $2}' | head -1)
  [[ -n "${src:-}" ]] && r_pass "svc-ntp-src" "NTP 來源:$src" || r_warn "svc-ntp-src" "未指定內部 NTP 來源(GCB 建議指向機關授時伺服器,如 FHAD2/FHDC1)"
else
  r_fail "svc-timesync" "無時間同步服務運行"
  r_na "svc-ntp-src" "無時間同步服務運行,NTP 來源設定不適用(先修正 svc-timesync)"
fi

#===============================================================================
say_cat "7. 網路核心參數(sysctl)"
#===============================================================================
declare -A NP=(
  [net.ipv4.ip_forward]=0
  [net.ipv4.conf.all.send_redirects]=0
  [net.ipv4.conf.default.send_redirects]=0
  [net.ipv4.conf.all.accept_redirects]=0
  [net.ipv4.conf.default.accept_redirects]=0
  [net.ipv4.conf.all.secure_redirects]=0
  [net.ipv4.conf.all.accept_source_route]=0
  [net.ipv4.conf.all.log_martians]=1
  [net.ipv4.icmp_echo_ignore_broadcasts]=1
  [net.ipv4.icmp_ignore_bogus_error_responses]=1
  [net.ipv4.conf.all.rp_filter]=1
  [net.ipv4.tcp_syncookies]=1
)
for k in "${!NP[@]}"; do
  # 同時比對執行值與 /etc/sysctl.d 持久化值:只改執行值(sysctl -w)重開機會回退
  sck_sysctl "net-$k" "$k(GCB 值:${NP[$k]})" "$k" "${NP[$k]}"
done
if grep -q "ipv6.disable=1" /proc/cmdline; then
  r_pass "net-ipv6" "IPv6 已於核心層完全停用(GRUB ipv6.disable=1)——IPv6 相關 sysctl 項目以此替代措施整批符合"
else r_manual "net-ipv6" "IPv6 未整體停用——需逐項檢查 IPv6 sysctl(或依 SOP 執行初始化 C)"; fi

#===============================================================================
say_cat "8. 主機防火牆"
#===============================================================================
fw_ok=0
if [[ "$FAMILY" == "deb" ]]; then
  systemctl is-active ufw &>/dev/null && $SUDO ufw status | grep -q "Status: active" && fw_ok=1
  fw_name="UFW"
else
  systemctl is-active firewalld &>/dev/null && fw_ok=1
  fw_name="firewalld"
fi
if [[ $fw_ok -eq 1 ]]; then
  r_pass "fw-host" "$fw_name 啟用中"
else
  if pkg_ok ds-agent || pkg_ok ds_agent; then
    r_manual "fw-host" "$fw_name 未啟用——本環境以 Deep Security Firewall 為主機防火牆替代措施(需於 DSM 確認 Firewall 模組狀態與政策,並將本項列入 GCB 例外表)"
  else r_fail "fw-host" "無主機防火牆($fw_name 未啟用且無 DS Agent)"; fi
fi

#===============================================================================
say_cat "9. 日誌與稽核"
#===============================================================================
chk "log-journald" "systemd-journald 運行中" "systemctl is-active systemd-journald"
if systemctl is-active rsyslog &>/dev/null; then r_pass "log-rsyslog" "rsyslog 運行中"
else r_warn "log-rsyslog" "rsyslog 未運行(僅 journald;GCB 要求日誌落地與轉送,請確認)"; fi
if systemctl is-active auditd &>/dev/null; then
  r_pass "log-auditd" "auditd 運行中"
  # auditctl -l 無規則時輸出 "No rules";以輸出內容判斷,不用行數(行數 1 可能是真的載入了 1 條規則)
  rules_out=$($SUDO auditctl -l 2>/dev/null || true)
  rules=$(grep -cvE '^[[:space:]]*(No rules)?[[:space:]]*$' <<<"$rules_out")
  is_num "${rules:-}" || rules=0
  if (( rules > 0 )); then
    r_pass "log-audit-rules" "audit 規則已載入($rules 條)"
  else
    r_fail "log-audit-rules" "auditd 運行但無規則(auditctl -l:${rules_out:-無輸出};GCB 要求時間/帳號/權限/模組等監控規則)"
  fi
else
  if systemctl is-active auditbeat &>/dev/null; then
    r_manual "log-auditd" "auditd 未運行——本環境由 InTimeSec auditbeat 接管 audit 子系統收集稽核事件(GCB auditd 規則項需以 EDR 替代措施列例外;勿同時強開 auditd 以免與 auditbeat 衝突)"
  else r_fail "log-auditd" "auditd 與 auditbeat 均未運行(無系統稽核)"; fi
  r_na "log-audit-rules" "auditd 未運行(由 auditbeat 接管或無稽核子系統),audit 規則載入狀態不適用"
fi
grep -rqsE '^\s*[^#]*@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null \
  && r_pass "log-remote" "rsyslog 已設定遠端日誌轉送" \
  || r_manual "log-remote" "未設遠端日誌轉送——若日誌集中由 EDR/SIEM 收集,列替代措施;否則建議設定"

#===============================================================================
say_cat "10. SSH 伺服器(sshd 有效組態)"
#===============================================================================
if $SUDO sshd -T &>/dev/null; then
  SSHD=$($SUDO sshd -T 2>/dev/null)
  sck() { local id="$1" d="$2" k="$3" want="$4"; local got; got=$(grep -im1 "^$k " <<<"$SSHD" | awk '{$1="";print substr($0,2)}');
    [[ "${got,,}" == "${want,,}" ]] && r_pass "$id" "$d($k=$got)" || r_fail "$id" "$d(目前 $k=${got:-未設},GCB:$want)"; }
  # 數值型:非數值(含未設)一律判不符——bash 會把非數字當變數名解析成 0,造成假符合
  snck() { local id="$1" d="$2" k="$3" op="$4" want="$5"; local got; got=$(grep -im1 "^$k " <<<"$SSHD" | awk '{print $2}');
    if ! is_num "${got:-}"; then r_fail "$id" "$d(目前 $k=${got:-未設},非數值無法判定)"; return; fi
    if [ "$got" "$op" "$want" ]; then r_pass "$id" "$d($k=$got)"; else r_fail "$id" "$d(目前 $k=$got)"; fi; }
  # 數值區間型:逾時類參數 0 在 OpenSSH 代表「永不逾時/無限寬限」,不可視為符合,
  # 故要求 下限 ≤ 值 ≤ 上限
  snck_range() { local id="$1" d="$2" k="$3" lo="$4" hi="$5"; local got; got=$(grep -im1 "^$k " <<<"$SSHD" | awk '{print $2}');
    if ! is_num "${got:-}"; then r_fail "$id" "$d(目前 $k=${got:-未設},非數值無法判定)"; return; fi
    if (( 10#$got >= lo && 10#$got <= hi )); then r_pass "$id" "$d($k=$got)"
    else r_fail "$id" "$d(目前 $k=$got,應介於 $lo~$hi;0 代表停用逾時)"; fi; }
  sck  "ssh-root"      "禁止 root 直接登入(CIS 5.1.20)" permitrootlogin no
  snck "ssh-maxauth"   "登入嘗試次數上限 ≤4(CIS 5.1.16)" maxauthtries -le 4
  sck  "ssh-rhosts"    "忽略 rhosts(CIS U22 5.1.11/R9 5.1.13)" ignorerhosts yes
  sck  "ssh-hostbased" "禁用主機信任認證(CIS U22 5.1.10/R9 5.1.12)" hostbasedauthentication no
  sck  "ssh-emptypw"   "禁止空密碼(CIS 5.1.19)" permitemptypasswords no
  sck  "ssh-x11"       "停用 X11 轉送(CIS U22 5.1.8/R9 5.1.10 DisableForwarding)" x11forwarding no
  snck_range "ssh-alive"      "閒置逾時 ClientAliveInterval 1~900 秒(CIS U22 5.1.7/R9 5.1.9;STIG 600;0=永不逾時不符)" clientaliveinterval 1 900
  snck_range "ssh-alivecount" "ClientAliveCountMax 1~3(與 ClientAliveInterval 併用才會真正斷線)" clientalivecountmax 1 3
  snck_range "ssh-grace"      "LoginGraceTime 1~60 秒(CIS U22 5.1.13/R9 5.1.14;0=無限寬限不符)" logingracetime 1 60
  b=$(grep -im1 "^banner " <<<"$SSHD" | awk '{print $2}')
  [[ -n "$b" && "$b" != "none" ]] && r_pass "ssh-banner" "SSH 登入橫幅已設($b)" || r_fail "ssh-banner" "SSH 未設 Banner(GCB 要求指向警語檔)"
  grep -qi "^usepam yes" <<<"$SSHD" && r_pass "ssh-pam" "UsePAM 啟用" || r_fail "ssh-pam" "UsePAM 未啟用"
  # 演算法白名單(CIS U22 5.1.6/5.1.15/5.1.12;R9 5.1.4/5.1.6/5.1.5 / STIG UBTU-*-010417 系列):偵測弱演算法
  ciph=$(grep -im1 "^ciphers " <<<"$SSHD" | cut -d' ' -f2-)
  if grep -qiE '(3des|blowfish|arcfour|cast128|-cbc)' <<<"$ciph"; then
    r_fail "ssh-ciphers" "SSH Ciphers 含弱演算法(CBC/3DES/arcfour 應移除;CIS U22 5.1.6/R9 5.1.4):$ciph"
  else r_pass "ssh-ciphers" "SSH Ciphers 無弱演算法(CIS U22 5.1.6/R9 5.1.4)"; fi
  macs=$(grep -im1 "^macs " <<<"$SSHD" | cut -d' ' -f2-)
  # hmac-sha1 為 hmac-sha1-96 / hmac-sha1-etm@openssh.com 的前綴,直接比對即可涵蓋所有變體;
  # 且不會誤命中 hmac-sha2-*(原本的 hmac-sha1[^0-9-] 反而漏掉 -etm 變體)
  if grep -qiE '(hmac-md5|hmac-sha1|umac-64)' <<<"$macs"; then
    r_fail "ssh-macs" "SSH MACs 含弱演算法(MD5/SHA1/umac-64 應移除,含 -etm 變體;CIS U22 5.1.15/R9 5.1.6):$macs"
  else r_pass "ssh-macs" "SSH MACs 無弱演算法(CIS U22 5.1.15/R9 5.1.6)"; fi
  kex=$(grep -im1 "^kexalgorithms " <<<"$SSHD" | cut -d' ' -f2-)
  # sha1 只出現在弱演算法名稱中(強者為 sha2/sha256/sha512),直接比對子字串以涵蓋
  # diffie-hellman-group-exchange-sha1 位於清單中段、結尾帶空白等情形
  if grep -qiE '(sha1|group1-)' <<<"$kex"; then
    r_fail "ssh-kex" "SSH KexAlgorithms 含弱演算法(SHA1/group1 應移除;CIS U22 5.1.12/R9 5.1.5):$kex"
  else r_pass "ssh-kex" "SSH KexAlgorithms 無弱演算法(CIS U22 5.1.12/R9 5.1.5)"; fi
else
  # sshd -T 失敗時不可讓整組 ssh-* 項目消失(項目不見=彙總看不到缺口),
  # 逐項輸出人工待判;不再使用目錄外的 ssh-config ID
  for _sid in ssh-root ssh-maxauth ssh-rhosts ssh-hostbased ssh-emptypw ssh-x11 \
              ssh-alive ssh-alivecount ssh-grace ssh-banner ssh-pam \
              ssh-ciphers ssh-macs ssh-kex; do
    r_manual "$_sid" "sshd -T 失敗,無法讀取 sshd 有效組態,本項無法判定(請確認 sshd 已安裝且組態可解析)"
  done
fi

#===============================================================================
say_cat "11. PAM 與密碼原則"
#===============================================================================
if [[ "$FAMILY" == "deb" ]]; then
  chk "pam-pwquality" "libpam-pwquality 已安裝" "pkg_ok libpam-pwquality"
else
  chk "pam-pwquality" "libpwquality 已安裝" "pkg_ok libpwquality"
fi
# pwquality 讀主檔 + conf.d(RHEL authselect 慣用 conf.d 覆寫)
pwq() { grep -hsE "^\s*$1" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tail -1; }
ml=$(pwq minlen | grep -oE '[0-9]+' | tail -1)
if is_num "${ml:-}" && (( 10#$ml >= 14 )); then
  r_pass "pam-minlen" "密碼最小長度 minlen=$ml(CIS:≥14)"
else
  r_fail "pam-minlen" "密碼最小長度 minlen=${ml:-未設}(CIS 要求 ≥14;STIG 15)"
fi
# pwquality 複雜度四項(CIS:各類字元至少 1 個,值為 -1)。
# CIS 稽核同時接受 minclass≥4(要求四類字元)作為等價替代,故先判 minclass。
mc=$(pwq minclass | grep -oE '[0-9]+' | tail -1)
if is_num "${mc:-}" && (( 10#$mc >= 4 )); then
  for cred in dcredit ucredit lcredit ocredit; do
    r_pass "pam-$cred" "密碼複雜度 ${cred}:以 minclass=$mc 等價滿足(CIS 允許 minclass≥4 取代四類 credit)"
  done
else
  for cred in dcredit ucredit lcredit ocredit; do
    cv=$(pwq "$cred" | grep -oE '\-?[0-9]+' | tail -1)
    if is_int "${cv:-}" && (( cv <= -1 )); then
      r_pass "pam-$cred" "密碼複雜度 ${cred}=${cv}(CIS)"
    else
      r_fail "pam-$cred" "密碼複雜度 ${cred}=${cv:-未設}(CIS 要求 -1,或改用 minclass≥4)"
    fi
  done
fi
# faillock 門檻取值:先讀 /etc/security/faillock.conf,取不到再自 PAM stack 行內參數取
fl_val() {
  local key="$1" v=""
  v=$(grep -hsE "^[[:space:]]*${key}[[:space:]]*=" /etc/security/faillock.conf 2>/dev/null \
      | tail -1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')
  if ! is_num "${v:-}"; then
    v=$(grep -hsoE "${key}=[0-9]+" /etc/pam.d/common-auth /etc/pam.d/system-auth \
        /etc/pam.d/password-auth 2>/dev/null | tail -1 | cut -d= -f2)
  fi
  is_num "${v:-}" && printf '%s' "$v"
}
# 已確認 PAM stack 掛載 pam_faillock 後,再檢查鎖定門檻(CIS:deny ≤5、unlock_time ≥900)
fl_report() {
  local deny unlock
  deny=$(fl_val deny); unlock=$(fl_val unlock_time)
  if ! is_num "${deny:-}" || ! is_num "${unlock:-}"; then
    r_warn "pam-faillock" "pam_faillock 已掛載於 PAM stack,但取不到鎖定門檻(deny=${deny:-未設}、unlock_time=${unlock:-未設};CIS 要求 deny≤5 且 unlock_time≥900)"
  elif (( 10#$deny >= 1 && 10#$deny <= 5 )) && (( 10#$unlock == 0 || 10#$unlock >= 900 )); then
    r_pass "pam-faillock" "登入失敗鎖定 pam_faillock 已設定(deny=$deny、unlock_time=$unlock;0 代表須管理者手動解鎖)"
  else
    r_warn "pam-faillock" "pam_faillock 已掛載但門檻不符(目前 deny=$deny、unlock_time=$unlock;CIS 要求 deny 介於 1~5 且 unlock_time≥900 或 0)"
  fi
}
if [[ "$FAMILY" == "deb" ]]; then
  if grep -qsE '^[[:space:]]*[^#].*pam_faillock' /etc/pam.d/common-auth; then fl_report
  else r_fail "pam-faillock" "common-auth 未掛載 pam_faillock(GCB 要求失敗次數鎖定)"; fi
  grep -qs "pam_pwhistory" /etc/pam.d/common-password && r_pass "pam-history" "密碼歷史記錄 pam_pwhistory 已設定" \
    || r_warn "pam-history" "未設定密碼歷史記錄(GCB 建議記住 ≥3 次)"
else
  # RHEL 8.2+:authselect + /etc/security/faillock.conf(CIS deny=5、unlock_time=900)。
  # faillock.conf 有參數但 PAM stack 沒掛 pam_faillock 時鎖定完全不生效,故 conf 只能是補充條件
  if grep -qsE '^[[:space:]]*[^#].*pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth; then fl_report
  else r_fail "pam-faillock" "system-auth/password-auth 未掛載 pam_faillock,鎖定不會生效(authselect enable-feature with-faillock)"; fi
  if grep -qs "pam_pwhistory" /etc/pam.d/system-auth /etc/pam.d/password-auth \
     || grep -qsE '^\s*remember\s*=' /etc/security/pwhistory.conf 2>/dev/null; then
    r_pass "pam-history" "密碼歷史記錄 pam_pwhistory 已設定"
  else r_warn "pam-history" "未設定密碼歷史記錄(GCB 建議記住 ≥3 次)"; fi
fi
em=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}')
[[ "$em" =~ ^(SHA512|YESCRYPT)$ ]] && r_pass "pam-hash" "密碼雜湊演算法:$em" || r_fail "pam-hash" "密碼雜湊演算法:${em:-未設}(應為 SHA512 或 YESCRYPT)"

#===============================================================================
say_cat "12. 使用者帳號與環境"
#===============================================================================
gv() { grep -E "^\s*$1\b" /etc/login.defs | awk '{print $2}'; }
pmax=$(gv PASS_MAX_DAYS); pmin=$(gv PASS_MIN_DAYS); pwarn=$(gv PASS_WARN_AGE)
# 數值比較一律先驗純數字(login.defs 值異常時不可退化成 0 而誤判符合)
is_num "${pmax:-}"  && (( 10#$pmax <= 90 )) && r_pass "acct-passmax" "PASS_MAX_DAYS=$pmax(GCB ≤90)"   || r_fail "acct-passmax" "PASS_MAX_DAYS=${pmax:-未設}(GCB ≤90)"
is_num "${pmin:-}"  && (( 10#$pmin >= 1 ))  && r_pass "acct-passmin" "PASS_MIN_DAYS=$pmin"            || r_fail "acct-passmin" "PASS_MIN_DAYS=${pmin:-未設}(GCB ≥1)"
is_num "${pwarn:-}" && (( 10#$pwarn >= 7 )) && r_pass "acct-passwarn" "PASS_WARN_AGE=$pwarn"          || r_fail "acct-passwarn" "PASS_WARN_AGE=${pwarn:-未設}(GCB ≥7)"
# login.defs 只作用於「新建」帳號,既有帳號的到期日要直接讀 /etc/shadow 第 5 欄
sh_tot=$($SUDO awk -F: '$2 ~ /^\$/{c++} END{print c+0}' /etc/shadow 2>/dev/null)
pm_bad=$($SUDO awk -F: '$2 ~ /^\$/ { if ($5 == "" || $5 !~ /^[0-9]+$/ || $5+0 > 90) print $1 }' /etc/shadow 2>/dev/null | tr '\n' ' ')
pm_n=$(printf '%s' "$pm_bad" | wc -w)
if ! is_num "${sh_tot:-}"; then
  r_manual "acct-passmax-existing" "無法讀取 /etc/shadow,既有帳號密碼最長使用期限無法判定"
elif (( sh_tot == 0 )); then
  r_na "acct-passmax-existing" "無設有密碼雜湊的一般帳號(僅金鑰或鎖定帳號),既有帳號密碼期限不適用"
elif (( pm_n == 0 )); then
  r_pass "acct-passmax-existing" "既有帳號密碼最長使用期限均 ≤90 天(共檢查 $sh_tot 個有密碼帳號)"
else
  r_fail "acct-passmax-existing" "有 $pm_n 個既有帳號密碼期限 >90 天或未設:${pm_bad}(GCB ≤90;chage -M 90 <帳號>)"
fi
um=$(gv UMASK)
# CIS 原文為「027 or more restrictive」:凡包含 027 所有限制位元者(如 077)皆符合
if [[ "${um:-}" =~ ^[0-7]{3,4}$ ]] && (( (8#$um & 8#027) == 8#027 )); then
  r_pass "acct-umask" "預設 UMASK=$um(027 或更嚴格;CIS)"
else
  r_fail "acct-umask" "預設 UMASK=${um:-未設}(CIS 要求 027 或更嚴格)"
fi
# TMOUT 需取實際數值判斷(TMOUT=99999 等同未設);同時支援 export/readonly 寫法
tm=$(grep -rhsE '^[[:space:]]*(export[[:space:]]+|readonly[[:space:]]+)*TMOUT=' \
       /etc/profile /etc/profile.d/ /etc/bash.bashrc /etc/bashrc 2>/dev/null \
     | sed -E 's/.*TMOUT=([0-9]+).*/\1/' | grep -E '^[0-9]+$' | tail -1)
if ! is_num "${tm:-}"; then
  r_fail "acct-tmout" "未設定 TMOUT 或取不到數值(GCB 要求 1~900 秒)"
elif (( 10#$tm >= 1 && 10#$tm <= 900 )); then
  r_pass "acct-tmout" "Shell 閒置逾時 TMOUT=$tm 秒(GCB ≤900)"
else
  r_fail "acct-tmout" "Shell 閒置逾時 TMOUT=$tm 秒不符(GCB 要求 1~900)"
fi
uid0=$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')
[[ "$uid0" == "root " ]] && r_pass "acct-uid0" "UID 0 僅 root" || r_fail "acct-uid0" "UID 0 帳號異常:$uid0"
empty=$($SUDO awk -F: '($2==""){print $1}' /etc/shadow | wc -l)
[[ "$empty" -eq 0 ]] && r_pass "acct-emptypw" "無空密碼帳號" || r_fail "acct-emptypw" "存在 $empty 個空密碼帳號"
grep -qs "pam_wheel" /etc/pam.d/su && r_pass "acct-su" "su 已限制群組(pam_wheel)" \
  || r_warn "acct-su" "su 未限制特定群組(GCB 建議 pam_wheel + 空成員群組)"

#===============================================================================
say_cat "13. cron / at"
#===============================================================================
if [[ -f /etc/crontab ]]; then
  p=$(stat -c '%a' /etc/crontab)
  perm_ok "$p" 600 && r_pass "cron-crontab" "/etc/crontab 權限 $p" \
    || r_fail "cron-crontab" "/etc/crontab 權限 $p(不得含 600 以外的權限位元)"
else
  r_na "cron-crontab" "/etc/crontab 不存在(此項不適用)"
fi
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  _cid="cron-dir-${d##*/}"
  if [[ -d $d ]]; then
    p=$(stat -c '%a' "$d")
    perm_ok "$p" 700 && r_pass "$_cid" "$d 權限 $p" \
      || r_fail "$_cid" "$d 權限 $p(不得含 700 以外的權限位元,如 group/other 的 r-x)"
  else
    r_na "$_cid" "$d 不存在(此項不適用)"
  fi
done
[[ -f /etc/cron.allow ]] && r_pass "cron-allow" "/etc/cron.allow 存在(白名單制)" \
  || r_fail "cron-allow" "/etc/cron.allow 不存在(GCB 要求白名單制並限 root 讀寫)"
if pkg_ok at; then
  [[ -f /etc/at.allow ]] && r_pass "cron-at" "/etc/at.allow 存在" || r_fail "cron-at" "/etc/at.allow 不存在(已裝 at 套件)"
else r_na "cron-at" "at 套件未安裝(at.allow 項不適用)"; fi

#===============================================================================
say_cat "14. 關鍵檔案權限"
#===============================================================================
pchk() { local id="$1" f="$2" maxp="$3" wantog="$4"
  [[ -e $f ]] || { r_fail "$id" "$f 不存在"; return; }
  local p og; p=$(stat -c '%a' "$f"); og=$(stat -c '%U:%G' "$f")
  # 八進位逐位判斷:606 不得因「606 ≤ 644」被當成符合(other 有寫入權限)
  if perm_ok "$p" "$maxp" && [[ "$og" == "$wantog" ]]; then
    r_pass "$id" "$f 權限 $p $og"
  else
    r_fail "$id" "$f 權限 $p $og(不得含 $maxp 以外的權限位元,擁有者應為 $wantog)"
  fi
}
pchk perm-passwd  /etc/passwd  644 root:root
pchk perm-group   /etc/group   644 root:root
if [[ "$FAMILY" == "deb" ]]; then
  pchk perm-shadow  /etc/shadow  640 root:shadow
  pchk perm-gshadow /etc/gshadow 640 root:shadow
else
  # CIS RHEL 9 §7.1.5/§7.1.7:shadow/gshadow 0000 root:root
  pchk perm-shadow  /etc/shadow  0 root:root
  pchk perm-gshadow /etc/gshadow 0 root:root
fi
if [[ "${SLOW:-0}" == "1" ]]; then
  # find / -xdev 不會跨進 /var、/home 等獨立掛載——分割做得越合規、漏掉的越多。
  # 改為列出本機實體掛載點(排除虛擬檔案系統與網路掛載)逐一掃描後加總。
  scan_mps=$(findmnt -rn -o TARGET,FSTYPE 2>/dev/null | awk '
    $2 ~ /^(proc|sysfs|devtmpfs|devpts|tmpfs|ramfs|cgroup|cgroup2|securityfs|pstore|bpf|debugfs|tracefs|configfs|fusectl|hugetlbfs|mqueue|autofs|binfmt_misc|efivarfs|rpc_pipefs|selinuxfs|nsfs|overlay|squashfs|iso9660|nfs|nfs4|cifs|smb3|glusterfs|ceph)$/ {next}
    $2 ~ /^fuse\./ {next}
    {print $1}' | sort -u)
  [[ -z "${scan_mps:-}" ]] && scan_mps="/"
  mp_n=0; ww=0; uo=0
  while IFS= read -r mp; do
    [[ -n "$mp" && -d "$mp" ]] || continue
    mp_n=$((mp_n+1))
    n=$($SUDO find "$mp" -xdev -type f -perm -0002 2>/dev/null | wc -l); ww=$((ww+n))
    n=$($SUDO find "$mp" -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l); uo=$((uo+n))
  done <<<"$scan_mps"
  [[ "$ww" -eq 0 ]] && r_pass "perm-ww" "無 world-writable 檔案(已掃描 $mp_n 個本機掛載點)" || r_warn "perm-ww" "world-writable 檔案 $ww 個(已掃描 $mp_n 個本機掛載點;以 sudo find <掛載點> -xdev -type f -perm -0002 檢視)"
  [[ "$uo" -eq 0 ]] && r_pass "perm-unowned" "無無主檔案(已掃描 $mp_n 個本機掛載點)" || r_warn "perm-unowned" "無主檔案 $uo 個(已掃描 $mp_n 個本機掛載點,建議清查)"
else
  r_manual "perm-scan" "world-writable / 無主檔案全磁碟掃描已略過(SLOW=1 重跑可含此項)"
fi

#===============================================================================
say_cat "15. GNOME GUI 項目"
#===============================================================================
if pkg_ok gnome-shell || pkg_ok ubuntu-desktop; then r_warn "gui-desktop" "偵測到桌面環境——GNOME GUI 章節項目需另行檢查"
else r_na "gui-desktop" "無桌面環境(Server)——GNOME GUI 章節整章不適用"; fi

#===============================================================================
# 總結
#===============================================================================
TOTAL=$((C_PASS+C_FAIL+C_WARN+C_MANUAL+C_NA))
echo -e "\n${CC}━━━━━━━━━━ 檢查總結 ━━━━━━━━━━${CN}"
printf "  共 %d 項:${CG}符合 %d${CN}/${CR}不符 %d${CN}/${CY}注意 %d${CN}/${CM}人工判定 %d${CN}/不適用 %d\n" \
  "$TOTAL" "$C_PASS" "$C_FAIL" "$C_WARN" "$C_MANUAL" "$C_NA"
if [[ ${#FAIL_LIST[@]} -gt 0 ]]; then
  echo -e "\n  ${CR}不符項目清單:${CN}"
  for i in "${FAIL_LIST[@]}"; do echo "   ✗ $i"; done
fi
cat <<'EOF'

  說明:
  - 本腳本未做任何變更,可安全重複執行。
  - [人工] 項目為本環境替代措施(DS Firewall / DS IM / auditbeat / GRUB 停用 IPv6),
    依 GCB 制度可列入「套用例外表」陳核,不必強行雙重設定。
  - 修正順序建議:先處理低風險項(橫幅/權限/login.defs/sysctl),
    SSH 與 PAM 項需通知使用者後再改,分割項留待重灌時規劃。
EOF

#===============================================================================
# JSON 輸出(平台模式:UCC_JSON_OUT=<路徑>)
#===============================================================================
if [[ -n "${UCC_JSON_OUT:-}" ]]; then
  json_escape() { local s="$1"
    s=${s//\\/\\\\}; s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
    # 其餘控制字元(U+0000–U+001F,含 ESC 與 US 分隔字元)在 JSON 字串中非法,
    # 統一轉為空白,避免整份報告因單一控制字元無法解析
    s=$(printf '%s' "$s" | tr '\001-\010\013\014\016-\037' ' ')
    printf '%s' "$s"
  }
  {
    printf '{'
    printf '"script_version":"%s",' "$SCRIPT_VERSION"
    printf '"hostname":"%s",' "$(json_escape "$(hostname)")"
    printf '"os":"%s",' "$(json_escape "$OS_PRETTY")"
    printf '"kernel":"%s",' "$(json_escape "$(uname -r)")"
    printf '"family":"%s",' "$FAMILY"
    printf '"started_at":"%s","finished_at":"%s",' "$STARTED_AT" "$(date -Is)"
    printf '"slow":%s,' "$([[ "${SLOW:-0}" == "1" ]] && echo true || echo false)"
    printf '"summary":{"pass":%d,"fail":%d,"warn":%d,"manual":%d,"na":%d,"total":%d},' \
      "$C_PASS" "$C_FAIL" "$C_WARN" "$C_MANUAL" "$C_NA" "$TOTAL"
    printf '"items":['
    first=1
    while IFS="$US" read -r iid icat istat idesc; do
      [[ $first -eq 1 ]] && first=0 || printf ','
      printf '{"id":"%s","cat":"%s","status":"%s","desc":"%s"}' \
        "$(json_escape "$iid")" "$(json_escape "$icat")" "$istat" "$(json_escape "$idesc")"
    done < "$ITEMS_TMP"
    printf ']}'
  } > "$UCC_JSON_OUT"
  echo -e "\n  JSON 結果已輸出:$UCC_JSON_OUT"
fi

# BaselineGuard — 組態基線稽核平台(GCB/CIS/STIG)

集中管理受檢設備的組態基準合規檢查:受檢端**只稽核、零改動**,結果集中入庫,
提供合規儀表板、歷次差異比較、跨主機不符彙總與長期設定變更軸。
支援 **Linux 主機兩大系**與 **9 型網路/管理設備**(防火牆、ADC、交換器、
虛擬化管理、儲存等,走各廠管理 API 或 SSH CLI)。

> 內部代號 `ucc`:檢查腳本、環境變數 `UCC_*`、安裝路徑 `/opt/ucc`、
> 回報 token header `X-UCC-*`、資料庫檔名 `configcheck.db` 皆沿用此代號。

## 受檢對象與依據

**Linux 主機**(單一檢查腳本自動偵測發行版,deb/rpm 雙分支):

- **Ubuntu / Debian**:TWGCB-01-014《Ubuntu 22.04 LTS 政府組態基準》v1.2、
  CIS Ubuntu 22.04 Benchmark v2.0.0 / 24.04 v1.0.0,交叉參照 DISA STIG
- **RHEL / Rocky / AlmaLinux**:CIS RHEL 9 Benchmark v2.0.0(SELinux、
  firewalld、dnf-automatic、gpgcheck、system-auth/faillock.conf、
  shadow 0000 root:root 等 RHEL 專屬檢查)

兩系共用穩定檢查項 ID(sysctl/SSH/帳號/權限等通用項可跨發行版彙總比較),
發行版特有項目(AppArmor↔SELinux、UFW↔firewalld 等)各有專屬 ID。出處欄
依 CIS Ubuntu 22.04 / RHEL 9 v2.0.0 原文標註精確條次。

**網路/管理設備**(合計 139 檢查項,只管設備自身管理面強化,不碰 policy 內容):

| 類型 | 連線 | 主要依據 |
|---|---|---|
| FortiGate 防火牆 | REST API | CIS FortiGate 7.4.x v1.0.1 + DISA FGFW-ND STIG |
| PaloAlto 防火牆 | XML API | CIS PAN-OS 11 v1.2.0 + DISA PANW-NM STIG |
| F5 BIG-IP | iControl REST | CIS F5 v1.0.0 + DISA F5BI-DM STIG |
| Citrix NetScaler | NITRO REST | Citrix Secure Deployment Guide + NDM SRG |
| Cisco 交換器 | SSH CLI | CIS Cisco IOS-XE 17.x v2.2.1 + DISA CISC-ND STIG |
| Aruba 控制器 | REST API | Aruba Hardening + DISA ARBA-ND STIG |
| vCenter | REST API | DISA vCenter STIG(VCSA appliance 管理面) |
| NetApp ONTAP | REST API | NetApp TR-4569 + DISA NAOT STIG |
| FortiAuthenticator | SSH CLI | FAC Admin Guide + NDM SRG |

**判定基準**:以 **CIS 為判定主軸**;同一控制項若 STIG 要求較嚴(密碼 15、
逾時 ≤5 分、syslog/NTP ≥2 台、時區須 UTC 等),STIG 值以**附加參照**併入
出處欄註記,判定門檻仍採 CIS,避免非 DOD 環境誤報。

## 兩種檢查模式(可混用)

| | Agent 回報 | SSH / API 連入 |
|---|---|---|
| 適用 | 伺服器連不進去的 Linux 主機 | 可從伺服器連入的 Linux 主機與所有網路設備 |
| 部署 | 主機詳情頁複製一鍵安裝指令,目標機 root 執行一次 | 免部署,填入連線帳密/私鑰/API token |
| 觸發 | 目標機 systemd timer 每日定時(設定頁調整時間) | 排程間隔(每台可調)+ 手動「立即檢查」 |
| 方向 | 主機 → 伺服器 8074 埠 POST 回報 | 伺服器 → 設備(SSH 22/自訂埠 或 管理 API) |
| 憑證 | 每台專屬 token(可重新產生) | 密碼、私鑰(Ed25519/ECDSA/RSA,可含 passphrase)或 API token;非 root 需 sudo |

Linux 主機可選 Agent 或 SSH;網路設備一律走設備管理 API / CLI。連線憑證
**逐台獨立填寫**,平台不提供全域預設帳密(空白 = 未設,一望即知連不連得上)。

> **腳本完整性**:兩埠皆為純 HTTP,Agent 每日以 root 執行從 `/script`
> 取回的腳本。`/script` 回應附帶 `X-UCC-Sig: HMAC-SHA256(key=該主機 token,
> msg=腳本內容)`,Agent 端以 `openssl dgst` 自算比對,**不符即拒絕更新、
> 沿用本機既有版本**,防止管理網段 MITM 對全機群下達 root 指令。已部署的
> 舊 Agent 需重跑一次一鍵安裝指令才獲得此保護(伺服器端向後相容)。

## 服務埠

| 埠 | 用途 |
|---|---|
| **8073** | Web UI(登入後操作介面) |
| **8074** | Agent 回報 API(token 驗證,無登入;`/install`、`/script`、`/report`) |

改埠:`config.json` 加 `"web_port"` / `"agent_api_port"`(或環境變數
`UCC_WEB_PORT` / `UCC_AGENT_API_PORT`)後重啟。兩埠同一程序、共用 DB 與排程。

## 安裝與啟動

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

瀏覽 `http://<伺服器>:8073`,首次以本機帳號 `admin` / `admin` 登入
(**上線前務必至設定頁改密碼**),可於設定頁啟用 AD(NTLM)網域登入與帳號分權
(全功能 / 唯讀)。

## 功能頁面

UI/UX 採側欄主控台設計系統(亮/暗主題、零 CDN)。

- **儀表板**:檢查結果/主機狀態甜甜圈圖、近期組態異動、主機合規概況
  (含目標類型、合規趨勢、不符增減)、跨主機共通不符項 Top 10
- **主機管理**:新增/編輯主機、連線測試、立即檢查/完整檢查(含全磁碟慢速掃描)、
  Agent 一鍵安裝指令與 token 管理
- **不符彙總**:跨主機差距分析(不符/注意/人工判定分頁、匯出 CSV);「人工判定」頁
  可作為 GCB 例外清單(替代措施)陳核依據
- **檢查項目**:全部檢查項清單(Linux 兩系與各設備類型分頁,含出處條次),
  逐項可停用/啟用——停用項自下一次入庫起不再儲存與統計(即刻生效、不追溯歷史);
  操作寫入稽核紀錄
- **版本歷程**:各主機檢查結果的長期版本軸——只存**初始基線**與其後
  **每一次異動**(狀態變更/內容變更/新增/消失),不受紀錄保留天數清理;
  以「主機 + 項目 ID」篩選即可回溯單一設定的完整變更歷程(匯出 CSV)
- **紀錄**(兩分頁):**檢查紀錄** — 歷次執行清單與明細(主機/狀態篩選、頁內快速
  定位、原始報告全文、匯出 CSV)、與前次差異比較;**稽核紀錄** — 操作軌跡
- **設定**:AD 登入、排程與保留、Agent 檢查時間/失聯門檻、Telegram/SMTP 告警、帳號分權

## 告警

檢查執行失敗(連線/認證/執行錯誤)與 Agent 失聯(超過門檻未回報)時,經
Telegram 群組與/或 SMTP 系統收件人告警(轉態去重,可選「恢復也通知」)。

## 資料與安全

- SQLite(`data/configcheck.db`,WAL 模式);主機憑證(SSH 密碼/私鑰/sudo 密碼/
  API token/Agent token)與 config.json 內的 secret 一律 AES-256-GCM 加密落地,
  金鑰在 `data/secret.key` —— **備份 DB 務必連同金鑰**,遺失金鑰密文不可復原。
- 檢查腳本與設備 driver **全程唯讀**:只稽核、不修改任何設定;SSH 模式僅在
  目標機 /tmp 產生暫存腳本與結果檔,執行後即刪除。
- 檢查/稽核紀錄依保留天數自動清理(預設 365 天);版本歷程不受此清理,長期保存。

## Agent 目標機需求

Ubuntu 22.04/24.04 或 RHEL/Rocky/Alma 8/9(bash、curl、systemd、openssl;
皆為預設內建)。安裝內容:`/opt/ucc/`(設定、wrapper、檢查腳本)+
`ucc-check.service/.timer`。移除:

```bash
systemctl disable --now ucc-check.timer
rm -rf /opt/ucc /etc/systemd/system/ucc-check.{service,timer}
systemctl daemon-reload
```

SSH 模式目標機需求:sshd 可達;帳號為 root,或具 sudo 權限(密碼或免密皆可)。
網路設備需開啟對應管理 API / SSH,並具備唯讀查詢權限的帳號或 token。

# Kaspersky Security Center → Wazuh SIEM

**English** | [Русский](README.ru.md)

Forwards critical Kaspersky Endpoint Security events (malware, network attacks, IOC, protection tampering) from **Kaspersky Security Center** to **Wazuh**: Syslog receiver, event normalization, detection and correlation rules. Alerts of level 10 and above go to the notifications configured in Wazuh (for example, Telegram).

Tested with: KSC Linux 16.3, KES for Windows 14.1, KESL 12.4, Wazuh 4.14.5.

---

## Contents

1. [Requirements](#1-requirements)
2. [Installation on the Wazuh manager](#2-installation-on-the-wazuh-manager)
3. [Kaspersky Security Center configuration](#3-kaspersky-security-center-configuration)
4. [Verification](#4-verification)
5. [deploy.sh commands](#5-deploysh-commands)
6. [Update and rollback](#6-update-and-rollback)
7. [Adding a new event type](#7-adding-a-new-event-type)

---

## 1. Requirements

- Wazuh manager 4.x (single node or cluster master), Linux with systemd, `bash`, `python3`, `iproute2`, root access.
- KSC Linux 16.x with the Web Console, administrator rights.
- Network access from the KSC server to the Wazuh manager over TCP 514.

---

## 2. Installation on the Wazuh manager

```bash
git clone https://github.com/V1p3rL0rd/ksc-integration-with-wazuh-siem.git
cd ksc-integration-with-wazuh-siem
cp config.env.example config.env
sudo chown root:root config.env && sudo chmod 600 config.env
sudo nano config.env          # KSC_IP: KSC server address, LISTEN_IP: Wazuh manager address
```

```bash
sudo ./deploy.sh plan         # show the changes
sudo ./deploy.sh install      # install
```

`install` adds a Syslog receiver for `KSC_IP` to `ossec.conf`, installs the decoder and rules, validates them with `wazuh-logtest` and restarts `wazuh-manager`. On any error the previous state is restored from a backup automatically.

If the Syslog receiver or the decoder/rule files were already configured manually, `plan` stops and shows what it found. In that case run:

```bash
sudo ./deploy.sh install --adopt
```

`config.env` settings:

| Key | Default | Description |
|---|---|---|
| `KSC_IP` | — | KSC server IP (required) |
| `LISTEN_IP` | — | Wazuh manager IP to listen on (required) |
| `SYSLOG_PORT` | `514` | Port |
| `SYSLOG_PROTOCOL` | `tcp` | `tcp` / `udp` |
| `OSSEC_DIR` | `/var/ossec` | Wazuh directory |
| `SERVICE_NAME` | `wazuh-manager` | systemd service |
| `BACKUP_ROOT` | `/root/ksc-integration-with-wazuh-siem-backups` | Backups |
| `BACKUP_KEEP` | `10` | Number of backups to keep |
| `RULE_ID_MIN` / `RULE_ID_MAX` | `100700` / `100799` | Rule ID range |
| `LOG_IGNORE_REGEX` | — | Unrelated `ossec.log` errors that are not treated as a failure |
| `AGENT_RECOVERY_TIMEOUT` | `180` | Time to wait for agents to reconnect, seconds |

---

## 3. Kaspersky Security Center configuration

Done in the KSC Web Console **after** the installation on Wazuh. Menu names follow the Web Console; the Russian labels are given in parentheses.

### 3.1. Export to SIEM

**Administration Server properties → General → Exporting events to SIEM system** (Свойства Сервера администрирования → Общие → Экспорт в SIEM-систему)

1. "Export events to SIEM" → **Enabled**.
2. **"Settings"** (Параметры):
   - SIEM system server address: `LISTEN_IP`;
   - Port: `514`;
   - Protocol: **TCP**;
   - Data format: **Syslog**;
   - Maximum message size: **8192**.
3. Close the window. Connection status: **"Connected"**.
4. "Start date of system event export": **do not set**.
5. **Save**.

### 3.2. Marking an event for export

**Assets (Devices) → Policies → policy → Event configuration → severity level** (Управление активами → Политики → политика → Настройка событий → уровень)

1. Select the events.
2. **"Mark for export to SIEM system via Syslog"** (Отметить для экспорта в SIEM-систему по протоколу syslog): a ✓ appears in the Syslog column.
3. The "Storage term" of every selected event must **not** be "Do not store" (for example, 30 days), otherwise the event is not exported.
4. **Save**.

Configure the policies in the "Managed devices" group. If a subgroup has its own KES policy, configure it too. Do not change the Network Agent policy.

### 3.3. KES for Windows: "Critical" level

<details>
<summary>Mark for export</summary>

| Event | Russian console label |
|---|---|
| AMSI request blocked | AMSI-запрос заблокирован |
| IOC detected | IOC обнаружен |
| Process action blocked | Действие процесса заблокировано… |
| Keyboard not authorized | Клавиатура не авторизована |
| Disinfection impossible | Лечение невозможно |
| Cannot be deleted | Невозможно удалить |
| Malicious object detected (KSN) | Обнаружен вредоносный объект (KSN) |
| Malicious object detected (local databases) | Обнаружен вредоносный объект (локальные базы) |
| Malicious object detected, active infection disinfection required on a virtual machine template | Обнаружен вредоносный объект. Требуется запуск процедуры лечения активного заражения на шаблоне виртуальной машины |
| Active threat detected, active infection disinfection required | Обнаружена активная угроза. Требуется запуск процедуры лечения активного заражения |
| Network attack detected | Обнаружена сетевая атака |
| Possible password brute-force attempt detected | Обнаружена возможная попытка взлома пароля с помощью подбора |
| Suspicious activity during a network logon session | Обнаружена подозрительная активность во время сетевого сеанса входа |
| Suspicious activity of a newly installed service | Обнаружена подозрительная активность со стороны новой установленной службы |
| Suspicious changes of the Administrators group | Обнаружены подозрительные изменения привилегированной группы Администраторы |
| Kerberos forged PAC attack (MS14-068) | Обнаружены признаки атаки Kerberos forged PAC (MS14-068) |
| Windows event log compromise | Обнаружены признаки компрометации журналов Windows |
| Object not blocked | Объект не заблокирован |
| Object not quarantined (Endpoint Detection and Response) | Объект не помещен на карантин (Endpoint Detection and Response) |
| Object not quarantined (Sandbox) | Объект не помещен на карантин (Sandbox) |
| Dangerous link opened | Открыта опасная ссылка |
| Previously opened dangerous link detected | Обнаружена ранее открытая опасная ссылка |
| Object deletion error | Ошибка удаления объекта |
| Process terminated | Процесс завершен |
| Suspicious event repeats too often, aggregation started | Подозрительное событие повторяется слишком часто. Запущено формирование агрегированных событий |
| Log Inspection rule triggered | Сработало правило Анализа журналов |
| *(optional)* Suspicious authentication with explicit credentials | Обнаружена подозрительная аутентификация с явным указанием учетных данных |

</details>

### 3.4. KES for Linux: "Critical" level

<details>
<summary>Mark for export</summary>

| Event | Russian console label |
|---|---|
| Threat detected | Обнаружена угроза |
| Network attack detected | Обнаружена сетевая атака |
| Encryption detected | Обнаружено шифрование |
| Indicators of compromise detected | Обнаружены индикаторы компрометации |
| Phishing website detected | Обнаружен фишинговый веб-сайт |
| Previously opened dangerous link detected | Обнаружена ранее открытая опасная ссылка |
| Application module integrity violated | Нарушена целостность модулей приложения |
| Application database integrity violated | Нарушена целостность баз приложения |
| File Threat Protection unavailable due to an interceptor driver error | Защита от файловых угроз недоступна из-за ошибки драйвера файлового перехватчика |
| Process terminated | Процесс завершен |
| Process not terminated | Процесс не завершен |

</details>

Do not mark the other "Critical" events (errors, updates, licenses, certificates, Application / Device / Web Control, firewall blocks).

### 3.5. Virus outbreak

1. **Administration Server properties → General → Virus outbreak** (Вирусная атака) → enable **"Anti-virus for workstations and file servers"** (10 viruses in 10 minutes) → Save.
2. **Administration Server properties → Event configuration → Critical** → "Virus outbreak" (Вирусная атака) → "Mark for export…" → Save.

---

## 4. Verification

```bash
sudo ./deploy.sh verify
```

End-to-end check:

1. On the manager:
   ```bash
   sudo tail -F /var/ossec/logs/alerts/alerts.json | grep --line-buffered '"kaspersky"' \
     | jq -c '{rule: .rule.id, level: .rule.level, desc: .rule.description}'
   ```
2. On a test computer create the [EICAR](https://www.eicar.org/download-anti-malware-testfile/) test file.
3. Within 2–5 minutes alert **100701** (level 10) and a notification are expected.

Rules:

| ID | Level | Event |
|---|---|---|
| 100709 | 10 | any event marked for export in KSC |
| 100701 | 10 | malicious object detected |
| 100702 | 3 | disinfection impossible (object deleted), no notification |
| 100710 | 13 | malicious objects on 3 or more different computers within 10 minutes |

---

## 5. deploy.sh commands

| Command | Action |
|---|---|
| `sudo ./deploy.sh plan` | show the changes without applying them |
| `sudo ./deploy.sh install` | install / update |
| `sudo ./deploy.sh test` | run the test events through `wazuh-logtest` |
| `sudo ./deploy.sh verify` | check the current state |
| `sudo ./deploy.sh rollback` | remove the integration |

| Option | Action |
|---|---|
| `-c FILE` | use another settings file |
| `--adopt` | take over a manually created configuration |
| `--no-restart` | do not restart `wazuh-manager` |
| `--from-backup DIR` | `rollback`: restore from the given backup |
| `-y` | do not ask for confirmation |

---

## 6. Update and rollback

Update:

```bash
git pull
sudo ./deploy.sh plan
sudo ./deploy.sh install
```

Rollback:

```bash
sudo ./deploy.sh rollback
# or from a specific backup:
sudo ./deploy.sh rollback --from-backup /root/ksc-integration-with-wazuh-siem-backups/<directory>
```

In KSC: **Administration Server properties → Exporting events to SIEM system** → "Export events to SIEM" → **Disabled** → Save.

---

## 7. Adding a new event type

1. Mark the event for export in KSC (section 3.2) and trigger it on a test computer.
2. Capture the event on the manager:
   ```bash
   sudo tcpdump -l -i any -nn -A -s0 'src host <KSC_IP> and tcp dst port 514' | tee /tmp/ksc-sample.txt
   sudo grep -aoE '<[0-9]+>1 .*<EVENT_CODE>.*' /tmp/ksc-sample.txt | head -1 | sed -E 's/^<[0-9]+>//' > tests/samples/<name>.log
   ```
3. Check how it is decoded: `sudo /var/ossec/bin/wazuh-logtest < tests/samples/<name>.log`.
4. If needed, add fields to `wazuh/decoders/kaspersky_ksc.xml` and a **child rule of 100709** to `wazuh/rules/kaspersky_ksc_rules.xml` (IDs 100700–100799).
5. Add the expected result to `tests/cases.json`, check with `sudo ./deploy.sh test`, apply with `sudo ./deploy.sh install`.

---

## License

MIT — see [LICENSE](LICENSE).

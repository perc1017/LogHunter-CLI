# 🛡️ SOC Sentinel

### Automated Web Log Analyzer for SOC

**SOC Sentinel** — Dockerized CLI-инструмент для автоматизации первичного анализа `Nginx access.log`.

Проект демонстрирует, как рутинную задачу **Tier 1 SOC** можно автоматизировать: вместо ручного просмотра тысяч HTTP-запросов инструмент самостоятельно анализирует логи, выявляет подозрительную активность, классифицирует события и выводит структурированный отчёт в терминал.

---

## 🎯 Что делает

SOC Sentinel анализирует web access logs и обнаруживает признаки:

* SQL Injection
* XSS
* SSRF
* Path Traversal / LFI
* RCE / Command Injection
* Brute-force
* Web scanners
* Mass 404 / path enumeration
* Suspicious User-Agent
* Multi-vector activity
* Аномальные IP

Для каждого события определяется уровень:

```text
LOW → MEDIUM → HIGH → CRITICAL
```

Дополнительно инструмент формирует статистику по IP, типам атак, HTTP-кодам и показывает наиболее подозрительные источники.

---

## ⚙️ Как это работает

```text
Nginx access.log
       ↓
   Log Parser
       ↓
 Normalization
       ↓
 Detection Rules
       ↓
 Correlation & Risk Analysis
       ↓
 Structured SOC Report
```

На выходе аналитик получает уже обработанные данные:

```text
Threats
Suspicious IPs
Attack Vectors
Brute-force
Scanners
Findings
Final Verdict
```

---

## 🐳 Запуск

Для работы нужны всего три файла:

```text
Dockerfile
requirements.txt
soc_sentinel.py
```

Сборка image:

```bash
docker build -t soc-sentinel .
```

Запуск анализа:

```bash
docker run --rm -it \
  -v /var/log/nginx:/logs:ro \
  soc-sentinel analyze /logs/access.log
```

### Что происходит

`-v /var/log/nginx:/logs:ro` подключает логи в контейнер **только для чтения**.

`--rm` автоматически удаляет контейнер после завершения анализа.

В результате workflow выглядит так:

```text
Docker Run
    ↓
Read Nginx Logs
    ↓
Analyze
    ↓
Print SOC Report
    ↓
Container Removed
```

---

## 🔍 Пример возможностей

Инструмент способен обнаружить, например:

```text
SQLi
GET /index.php?id=1' OR 1=1
```

```text
LFI
GET /../../../../etc/passwd
```

```text
SSRF
GET /?url=http://169.254.169.254/latest/meta-data/
```

```text
Scanner
User-Agent: sqlmap
```

```text
Brute-force
Multiple authentication attempts from one IP
```

После обработки события группируются и отображаются в удобном терминальном интерфейсе на базе `Rich`.

---

## 🛡️ SOC Use Case

Основная задача проекта:

```text
RAW LOGS
   ↓
AUTOMATED TRIAGE
   ↓
THREAT DETECTION
   ↓
PRIORITIZATION
   ↓
SOC ANALYST
```

Инструмент не заменяет SIEM/WAF/EDR. Его задача — **автоматизировать первичную обработку web-логов и выделить события, которые требуют внимания аналитика**.

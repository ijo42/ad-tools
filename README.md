# AD Toolkit — анализатор трафика + fast-track контр-атак

Тулкит участника Attack-Defense CTF на ForcAD. **Веб-интерфейс — основной
инструмент**: один процесс (`web.py --with-ingest --with-submitter`) = UI +
приём трафика + автопроверка на NPC + сабмиттер.

```
vulnbox (пассивный capture)              ноутбук: web.py — всё в одном
┌─────────────────────────┐              ┌─────────────────────────────────┐
│ tcpdump ─PCAP-over-IP───┼──tcp:57012──►│  web.py --with-ingest           │
│   (live, если доступен) │              │   ├ UI http://127.0.0.1:57020   │
│ tcpdump ─ротация 60с────┼──http:57013──┤   ├ analyzer → detections.db    │
│   (файлы для poll)      │              │   │    дедуп (2 уровня)         │
│                         │   ┌─poll─────┤   ├ NPC-автопроба детектов      │
│                         │   │ rsync/SSH│   ├ flags.queue.jsonl           │
└─────────────────────────┘   │ pull.sh  │   └ submitter-поток             │
                              └──────────┴─────────┬───────────────────────┘
                                                   ▼
                                              ForcAD /flags
```

Команды запускаются через `uv run` (зависимости подтягиваются на лету).
Внешние зависимости: `fastapi`, `uvicorn`, `pyyaml`; ядро — stdlib.
UI — Vue 3 SPA, вендорен в `webui/static/` (без CDN, работает офлайн).

## Возможности веб-интерфейса

Три вкладки:

- **Детекты**:
  - дедуп, два уровня: (1) *по шаблону* — тот же эксплойт на других флагах
    (чекер перекладывает флаги каждый раунд) и в других раундах — один
    детект (счётчик хитов, раунды, флаги, источники); (2) *по совпадению
    атаки* — другой шаблон, но тот же флаг в том же раунде (другая команда
    exploit'ит ту же уязвимость) — сливается в первый детект как «вариант»;
  - определение атакуемого сервиса (порт → имя из `game.services`); replay
    детекта идёт на одноимённый порт цели, а не на все порты;
  - NPC-автопроба: новый пейлоад сразу проверяется на NPC (npc: true в
    teams.yaml — флаги NPC очков не дают, п. 4.7). Колонка NPC: `✓ N`
    (эксплойт работает) / `✗ нет флагов` / `⏳` / `! недоступен`, кнопка ↻ —
    перепроверка; флаги NPC не попадают в очередь сдачи. Бюджет: ≤10 проб
    за минуту (сканерный шум не устраивает шторм на NPC); в шапке UI —
    **переключатель «NPC-автопроба»**: выключает автопробу новых детектов
    на лету (ручной ↻ продолжает работать);
  - атрибуция флагов: утёкший флаг привязывается к детекту (сервис +
    атакующий + раунд) — видно, какие флаги уже утащили; флаги, утёкшие
    ИЗ вашего сервиса (leak), не сдаются — это ваши же флаги;
  - разметка: метки (exploit / noise / patched / произвольные) + заметки,
    в т.ч. **массовая** (чекбоксы → «применить»);
  - фильтры: сервис / метка / раунд / наличие флагов / NPC-статус /
    поиск по payload, источникам и заметкам;
  - replay-кнопки: на все команды (verbatim/template) и на NPC (↻);
    флаги из ответов автоматически в очередь сабмиттера;
  - **клонер запроса**: pwntools-скрипт из payload одним кликом (правится и
    запускается отдельно: `uv run --with pwntools python clone_detN.py`) +
    отправка изменённого payload прямо из UI на указанный host:port.
- **Пакеты** — ВСЕ пакеты (даже без флагов) с метками раундов: фильтры
  (раунд / сервис / направление / флаг / текстовый поиск), пагинация,
  разделители «— раунд N —».
- **Аналитика** — офлайн-графики (inline SVG, без CDN): пакеты / утёкшие
  флаги / хиты детектов по раундам, топ-10 атакующих, сводка по сервисам.
- **Статус игры (шапка)** — монитор ForcAD API (`GET /api/client/config/`,
  endpoints проверены по исходникам ForcAD): текущий раунд и flag_lifetime
  в чипе, лента алертов (чекер вашей команды DOWN/MUMBLE/CORRUPT, игра не
  идёт, API недоступен), статистика сабмиттера (accepted/rejected с
  причинами). `game.start` калибруется по API, если не задан; просроченные
  флаги (flag_lifetime истёк) не отправляются.
- **Поиск флагов в обёртках** — extract_flags видит флаг в URL-кодировании,
  gzip/zlib-телах (в т.ч. внутри HTTP-ответа), UTF-16 и base64-блобах.
- **IPv6 и QinQ** — парсер понимает IPv6 (включая extension-заголовки) и
  802.1Q/QinQ-теги; pcapng распознаётся с внятной ошибкой (конвертируйте:
  `editcap -F pcap`).

API документация: http://127.0.0.1:57020/api/docs (FastAPI/OpenAPI).

## Подготовка (до зачётного старта)

1. **Конфиг**: скопируйте `laptop/config.example.yaml` → `laptop/config.yaml`
   (для docker — `config.docker.example.yaml` с путями `/app/data/...`),
   впишите адрес ForcAD, токен (п. 3.4), IP чекера в `analyzer.checker_ips`
   (иначе весь трафик считается атакой), порты своих сервисов в
   `game.services`, время старта в `game.start`.
2. **Цели**: скопируйте `laptop/teams.example.yaml` → `laptop/teams.yaml`:
   NPC-цель (`npc: true`) — обязательна для автопробе, адреса команд
   заполняются к зачётному старту (п. 3.3), NPC и disabled-записи
   исключаются из обычного replay.
3. **capture-время**: перед стартом передайте время начала зачёта
   (`GAME_START`, unix epoch) в capture (см. ниже) — файлы именуются
   `r{раунд}_p{part}_{ЧЧММСС}.pcap`; до старта — раунд 0. Окно записи —
   20 секунд (3 файла на раунд).
4. **pkappa2** входит в `laptop/docker-compose.yml` (UI
   http://127.0.0.1:2812).
5. **Репетиция**: `docker compose -f demo/docker-compose.yml up -d --build`
   (см. demo ниже).

## На vulnbox (пассивно — п. 8.9 регламента)

Основной путь — `vulnbox/capture.py`: один процесс читает поток tcpdump
(`-w -`) и сам режет его на файлы по окнам, именуя на момент записи
`r{раунд}_p{part}_{ЧЧММСС}.pcap`. Надёжность: нет гонок «renamer vs
tcpdump» (файл сразу создаётся с финальным именем), разделение по
таймстемпам pcap-записей (окно не «плывёт» под нагрузкой), автоперезапуск
tcpdump при обрыве, корректное закрытие по SIGTERM, пустые окна не создают
файлов.

**Docker (рекомендуется)**, из каталога `vulnbox/`:
```sh
# poll-режим: файлы в ./caps (забираются laptop/pull.sh или pull-профилем)
GAME_START=1764180000 IFACE=any docker compose up -d --build

# live-режим: стрим на ноутбук по PCAP-over-IP (:57012)
LAPTOP_IP=<IP_НОУТБУКА> GAME_START=1764180000 docker compose --profile live up -d
```

**Без Docker** (нужен python3 на vulnbox):
```sh
sudo python3 vulnbox/capture.py -i any -o /tmp/caps -s <GAME_START_EPOCH> -r 60 -w 20
```
Fallback без python3 — `vulnbox/capture.sh` (простой tcpdump, окно 20с,
служебные имена `cap_ЧЧММСС.pcap`, без вычисления раундов).

Все варианты — только пассивный просмотр: ничего не блокируется и не
фильтруется (п. 8.9), фильтр записи исключает ваш SSH и node-exporter
(п. 8.12).

## На ноутбуке (анализ + атаки — п. 3.6 регламента)

**Docker (рекомендуется)**, из каталога `laptop/`:
```sh
cp config.docker.example.yaml config.yaml    # пути /app/data/..., заполните
cp teams.example.yaml teams.yaml
docker compose up -d --build                 # webui (host network) + pkappa2
# poll-агент (если vulnbox не достучывается до ноутбука, сценарий 7):
VULNBOX=root@<vulnbox-ip> docker compose --profile pull up -d
# реальная сдача флагов: заполните forcad.team_token в config.yaml и
# перезапустите без WEB_DRY (по умолчанию в compose — dry)
WEB_DRY=0 docker compose up -d --force-recreate webui
```
UI http://127.0.0.1:57020; PCAP-over-IP :57012; HTTP-загрузка pcap :57013;
pkappa2 http://127.0.0.1:2812.

**Без Docker** (нужен только uv):
```sh
cd laptop

# ОСНОВНОЙ РЕЖИМ: один процесс = UI + приём трафика + сабмиттер
uv run --with fastapi,uvicorn,pyyaml python web.py --config config.yaml \
    --teams teams.yaml --with-ingest --with-submitter
# → UI http://127.0.0.1:57020; PCAP-over-IP :57012; HTTP-загрузка pcap :57013

# отдельный сабмиттер не нужен; для dry-прогона: --with-submitter --dry

# poll-агент: ./pull.sh root@<vulnbox-ip> http://127.0.0.1:57013/pcap
#   (файл отдаётся после стабилизации; состояние в ~/.ad-pull/)

# CLI-путь (ретроспектива/скрипты, см. PLAYBOOK.md):
uv run --with pyyaml python extract.py attack.pcap --checker-ips <IP_ЧЕКЕРА> \
    --payload 1 --out payload.bin
uv run --with pyyaml python replay.py --payload payload.bin \
    --teams teams.yaml --config config.yaml --submit
```

Раздельный запуск (если нужен ingest без UI): `uv run --with pyyaml python
ingest.py --config config.yaml --teams teams.yaml`, web.py тогда просто
читает ту же `detections.db`.

В консоли web.py/ingest: `[detect NEW]` — новый детект (сервис, источник),
`[detect dup#N]` — повтор известного эксплойта, `[flag->det#N]` — флаг
атрибуцирован детекту, `*** FLAG ***` — флаг в очереди сабмиттера.

В веб-интерфейсе: клик по строке детекта → payload целиком, NPC-статус,
варианты (слитые атаки), метка/заметка, кнопки replay (на команды) и ↻
(перепроверить NPC), клонер в pwntools, результаты прогонов по каждой цели.

## Demo (репетиция без инфраструктуры)

**Docker** (из каталога `ad-toolkit/`):
```sh
cp demo/config.demo.yaml demo/config.yaml
cp demo/teams.demo.yaml  demo/teams.yaml
docker compose -f demo/docker-compose.yml up -d --build
# «атака» с хоста (мок-сервисы опубликованы на 127.0.0.1):
python3 demo/fake_attacker.py
# capture (опционально, на хосте): python3 vulnbox/capture.py -i lo -o /tmp/caps
```
UI http://127.0.0.1:57020 — детекты shop/proto, NPC-проверка, вкладки
Пакеты и Аналитика.

**Без Docker**:
```sh
# 3 mock-«сервиса»: жертва 18080/18081, «команда» 28080/28081, NPC 38080/38081
python3 demo/vuln_service.py &
HTTP_PORT=28080 TCP_PORT=28081 python3 demo/vuln_service.py &
HTTP_PORT=38080 TCP_PORT=38081 python3 demo/vuln_service.py &

# «атака» под tcpdump (имитация того, что поймает vulnbox)
sudo tcpdump -i lo -U -s 0 -w /tmp/attack.pcap 'port 18080 or port 18081' &
python3 demo/fake_attacker.py && sudo pkill -f 'tcpdump -i lo'

# разбор + реплай + сухая сдача
cd laptop
cat > /tmp/demo_ingest.yaml <<EOF
forcad: {base_url: "http://127.0.0.1:5000", team_token: "TEST"}
flags: {regex: "[A-Z0-9]{31}="}
submit: {queue_file: /tmp/flags.queue.jsonl, state_file: /tmp/flags_seen.txt}
analyzer: {checker_ips: []}
game:
  start: $(date +%s)
  round_len: 60
  detections_db: /tmp/detections.db
  services: {18080: shop, 18081: proto}
EOF
cat > /tmp/teams.yaml <<EOF
teams:
  - {name: npc, host: 127.0.0.1, services: {web: 38080, raw: 38081}, npc: true}
  - {name: team-1, host: 127.0.0.1, services: {web: 28080, raw: 28081}}
EOF
# основной режим: один процесс = UI + приём трафика + сабмиттер (dry)
cd laptop
uv run --with fastapi,uvicorn,pyyaml python web.py --config /tmp/demo_ingest.yaml \
    --teams /tmp/teams.yaml --with-ingest --with-submitter --dry
```

Ожидаемый результат: в http://127.0.0.1:57020 появятся детекты `shop` (HTTP)
и `proto` (GETFLAG) со статусом NPC-проверки `✓ 1` (флаг NPC в панели) и
атрибуцированными флагами жертвы. Перезапустите victim (новый флаг) и
повторите атаку — детект `shop` останется один, но count станет 2 и
добавится новый раунд. Если другой шаблон добудет тот же флаг в том же
раунде — он сольётся с детектом как «вариант». Кнопка replay добудет флаги
с мок-команд в очередь сабмиттера (`source=replay:detN`).

## Локальный прогон против реального ForcAD (проверено)

Полный цикл проверен против настоящего [ForcAD](https://github.com/pomo-mondreganto/ForcAD):
capture → live-стрим → детект → NPC-проба → replay → **реальная сдача
`PUT /flags/`** → очки на скорборде ( Victim +FP, Enemy −FP,
StolenFlags в БД ForcAD).

```sh
git clone https://github.com/pomo-mondreganto/ForcAD.git ~/ForcAD
cd ~/ForcAD
```

1. **config.yml** (фрагменты; остальное — как в `config.yml.example`):
   ```yaml
   game:
     round_time: 10            # быстрые раунды для теста
     start_time: 2026-11-17T21:52:56   # БЕЗ кавычек и без +00:00:
                                       # control.py валидирует strict=True,
                                       # initializer требует naive datetime
   tasks:
     - checker: adshop/checker.py
       checker_type: hackerdom
       checker_timeout: 15
       gets: 2
       puts: 2
       places: 1               # mock хранит один «слот» флага
       name: shop
   teams:
     - {ip: 127.0.0.1, name: Victim}   # наш vulnbox (mock на loopback)
     - {ip: 127.0.0.2, name: Enemy}    # цель для NPC-пробы и replay
   ```
2. **Чекер** `checkers/adshop/checker.py` — см. рецепт ниже (hackerdom-протокол:
   `check/put/get`, вердикт = код возврата 101/102/103/104).
3. **Чекеры в host network** (цели на loopback хоста): в
   `docker-compose-fast.yml` сервису `celery` добавить `network_mode: host`
   и `environment: {POSTGRES_HOST: 127.0.0.1, REDIS_HOST: 127.0.0.1,
   RABBITMQ_HOST: 127.0.0.1}` (storages доступны на хосте через
   опубликованные порты).
4. **Мок-сервисы** (наш `demo/vuln_service.py` поддерживает `/putflag`,
   `/getflag`, уязвимость `/search?q='`):
   ```sh
   BIND=127.0.0.1 python3 demo/vuln_service.py &   # Victim
   BIND=127.0.0.2 python3 demo/vuln_service.py &   # Enemy (NPC/replay)
   ```
5. `python3 control.py setup && python3 control.py start --fast`,
   затем `python3 control.py print_tokens` → токены команд.
6. **Тулкит** (docker): `laptop/config.yaml` с путями `/app/data/...`,
   `forcad.base_url: http://127.0.0.1:8080`, `checker_ips: ["127.0.0.1"]`,
   `game.start` = epoch start_time; `teams.yaml` — NPC и цель на
   127.0.0.2; `WEB_DRY=0 docker compose up -d --build webui`.
7. **Атака**: `capture.py -i lo` на хосте + live-стрим
   (`tcpdump -i lo -w - | nc 127.0.0.1 57012`), атака с чужого источника
   (`s.bind(("127.0.0.2", 0))` → 127.0.0.1:18080) — детект в UI, NPC `✓`,
   replay → флаги Enemy в очереди → сабмиттер сдаёт → очки.

Нюансы интеграции с реальным ForcAD, обнаруженные при прогоне:
- флаги сдаются через **`PUT /flags/`** (не POST) — учтено в
  `adtool/submitter.py`;
- вердикт чекера = **код возврата** (101/102/103/104), stdout — публичное
  сообщение;
- для hackerdom-типа `private_flag_data` = **stdout сообщения put** — put
  обязан вернуть в stdout id, под которым флаг сохранён, иначе get всегда
  CORRUPT;
- `places` — число слотов: mock хранит один флаг → `places: 1` (правится
  и через admin API: `PUT /api/admin/tasks/1/` после login
  `POST /api/admin/login/` с `admin.username/password` из config.yml);
- для доступа к docker-сокету без root: `sudo chmod 666 /var/run/docker.sock`
  или usermod -aG docker.

## Ограничения регламента, зашитые в тулкит

| Пункт | Как соблюдается |
|---|---|
| 3.6 (атаки только с личных ПК) | весь атакующий код в `laptop/`, vulnbox только слушает |
| 8.9 (пассивный просмотр, без блокировки) | capture только читает пакеты, ничего не фильтрует |
| 8.11/8.12 (iptables, node-exporter) | скрипты не трогают сеть и исключают порт 9100 из записи |
| 4.1 (формат флага) | regex `[A-Z0-9]{31}=` |
| 4.3 (≤100 флагов, ≤10 КиБ, X-Team-Token) | `submitter.py` батчирует |
| 4.4 (квота 200/с, burst 400) | token bucket в `submitter.py` |
| 4.7 (NPC вне зачёта) | NPC-флаги не сдаются (source=npc только для автопробе), в replay NPC исключён |
| 8.5 (без мусорного трафика) | бюджет NPC-проб (≤10/мин), replay на порт сервиса детекта, просроченные флаги не отправляются |

## Безопасность самого тулкита

- Приём трафика по умолчанию слушает **127.0.0.1**; для live-стрима с
  vulnbox запустите с `--listen-ip 0.0.0.0` (docker: `LISTEN_IP=0.0.0.0`).
- Опциональные токены в config.yaml (`ingest.token` — заголовок
  `X-Ingest-Token` для HTTP-upload; `ingest.poip_token` — первые байты
  PCAP-over-IP-потока; `vulnbox/pcapstream.sh` шлёт его из `POIP_TOKEN=`),
  чтобы команды в игровой сети не могли инжектить поддельные pcap в ваш
  детектор.
- Retention (`retention:` в config) держит таблицы packets/variants/seen_flags
  в пределах лимитов — БД не растёт бесконечно при сканерном шуме.

## Структура

```
vulnbox/   capture.py (потоковый сплиттер pcap по окнам, раунды/part),
           capture.sh (fallback без python3), pcapstream.sh (live),
           Dockerfile, docker-compose.yml (capture + pcapstream profile)
laptop/
  adtool/  pcap.py (парсер pcap/PCAP-over-IP, stdlib), streams.py (реассемблинг
           TCP + HTTP), flags.py, analyzer.py (классификация чекер/атака),
           store.py (SQLite-детекты, 2 уровня дедупа, variants, NPC-статусы,
           пакеты, аналитика), autoprobe.py (NPC-автопроба), clone.py
           (pwntools-клонер), template.py, replay.py, submitter.py
  ingest.py / extract.py / replay.py / submitter.py         — CLI
  web.py                                                    — launcher (FastAPI+uvicorn)
  webui/    app.py, schemas.py, jobs.py, services.py,
            routers/ (detections, packets, system),
            static/ (index.html, app.js, app.css, vue.global.prod.js)
                                                            — Vue 3 SPA + REST API
  pull.sh                                                   — poll-режим (SSH/rsync)
  Dockerfile, docker-compose.yml (webui + pkappa2 + pull profile)
demo/      vuln_service.py, fake_attacker.py,
           docker-compose.yml (репетиционный стенд)         — dry-run
```

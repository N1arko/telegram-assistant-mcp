# Подробная инструкция для ИИ-агента

**Русский | [English](GETTING-STARTED.en.md)**

Эта инструкция описывает настройку Telegram Assistant MCP на вашем компьютере или VPS. Она рассчитана на ИИ-агента, который умеет работать с кодом и сервером. Пользователь не должен вручную перепечатывать длинные команды или разбираться в программировании.

## Обязательные ограничения

- Для описанной настройки всегда запускайте с `--read-only`. Не включайте отправку сообщений или иные операции записи.
- Не выводите в чат, логи или Git секреты, токены, коды входа и Telegram session. Для Telegram-кода и пароля 2FA попросите пользователя ввести их в скрытый локальный запрос; не принимайте их сообщением в чат.
- Не отправляйте Telegram-сообщения и не отмечайте сообщения прочитанными для тестирования.
- Не обещайте доступ ко всем каналам: broadcast-каналы по умолчанию скрыты.
- Не останавливайте уже работающий сервер без отдельного согласия пользователя.
- Объясняйте действия коротко. До покупки услуг, изменения доступа или иных расходов сначала сообщите пользователю, что понадобится.

## Краткая карта настройки

1. [Создание Telegram-сессии](#2-создайте-отдельную-telegram-сессию) — пользователь лично вводит Telegram-код и, если нужно, пароль двухэтапной проверки.
2. [Настройка OAuth API](#3-настройте-oauth-api-в-auth0) — в текущем примере используется Auth0 и только разрешение `telegram:read`.
3. [Подключение ChatGPT](#4-создайте-подключение-chatgpt) — пользователь входит в аккаунты и подтверждает согласия.
4. [Локальный запуск](#5-запустите-локально) и [Docker/TLS для удалённого ChatGPT](#6-docker-и-tls).
5. [Осторожная первая проверка и cooldown](#7-первый-вызов-и-cooldown) — соблюдайте ограничения запросов.

Для простого старта без подробностей отправьте пользователю [короткую инструкцию](START-HERE.ru.md).

# Руководство для первого запуска

Это руководство поможет запустить локальный read-only MCP для личных Telegram-диалогов и групп. Для подключения ChatGPT через интернет понадобится отдельный сервер с публичным HTTPS и защищённым обратным прокси. Локальный пример Docker ниже публикует порт только на loopback и сам по себе недоступен ChatGPT Web.

## Что делает сервер

В режиме `--read-only` доступны шесть инструментов: список диалогов, история выбранного диалога, поиск, контекст ответа, просмотр конкретного фото по явному запросу и опциональная транскрибация конкретного аудио по явному запросу. Каждый запрос проверяется по OAuth access token и ограничен по размеру и частоте. Контент Telegram следует считать недоверенными данными.

В коде также есть `send_message` и `send_media`, если отключить read-only режим и настроить разрешение и grant адресата. Эта инструкция их не включает; отправка в реальный Telegram не проверялась. Не активируйте отправку для описанного read-only сценария. Подробности реализации находятся в [server.py](../src/telegram_assistant/server.py), [security.py](../src/telegram_assistant/security.py) и [тестах](../tests/test_service.py). Локальные настройки политики описаны в [руководстве по отправке](SENDING-POLICY.ru.md).

Широковещательные каналы по умолчанию скрыты. В исходном коде есть внутренний read-only allowlist для ровно одного канала, но он выключен и не настраивается через публичный пример. Не включайте его без отдельной проверки нужного канала и прав владельца. `--read-only` не открывает отправку.

## Инструменты для медиа

`view_photo(peer_id, message_id)` получает фотографию только из конкретного выбранного сообщения. История, поиск и контекст ответа по-прежнему возвращают текст/подписи и `has_media`; вложения они не скачивают. Сервер проверяет размер по данным Telegram и реальную сигнатуру файла, отклоняет изображения больше 8 MiB или 12 мегапикселей, создаёт локальный JPEG preview не больше 1280 пикселей по длинной стороне и 256 KiB, затем возвращает нативный MCP `ImageContent`. Только HTTP-ответ этого инструмента может быть до 512 KiB; у всех остальных вызовов сохраняется лимит 48 KiB. Preview и результат кэшируются в памяти до пяти минут, временные файлы удаляются после вызова.

`transcribe_audio(peer_id, message_id)` доступен, но **по умолчанию выключен**. Принимаются только голосовые и аудиофайлы Telegram; сервер проверяет реальную сигнатуру и кодек, ограничивает файл размером 20 MiB и длительностью до пяти минут, а текст транскрипта кэширует в памяти до пяти минут. Голосовые OGG/Opus локально переупаковываются в WebM с копированием аудиопотока; декодирования для распознавания речи нет. Для этого нужны `ffmpeg`/`ffprobe`, они уже устанавливаются в Docker-шаблоне. Только выбранный файл передаётся настроенному API OpenAI после явного вызова инструмента. Другого провайдера и локального Whisper/ML нет. Используется модель `gpt-4o-mini-transcribe`. В [текущем руководстве OpenAI по транскрибации файлов](https://developers.openai.com/api/docs/guides/speech-to-text) перечислены форматы MP3, MP4, MPEG, MPGA, M4A, WAV и WebM, поэтому для OGG/Opus нужна переупаковка.

`send_media(peer_id, items, reply_to?)` отправляет одно фото JPEG/PNG, видео MP4/WebM, документ, аудио MP3/MP4/M4A/WAV/WebM/OGG-Opus, голосовое OGG/Opus, GIF-анимацию или статичный WebP-стикер. Также можно отправить альбом из 2–10 фото/видео. MCP-клиент передаёт байты файла в запросе как base64; путь на сервере не принимается. Сервис проверяет содержимое, контейнер, размеры и длительность, ограничивает один вызов 20 MiB и удаляет закрытые временные файлы после отправки. Фото ограничено 8 MiB/12 мегапикселями; видео/GIF — 12 мегапикселями на кадр и пятью минутами, аудио и голосовые — пятью минутами; статичный WebP-стикер — 512 KiB/512×512 пикселями. HTTP-запрос может быть до 32 MiB для base64 JSON; тело буферизуется только для одного запроса одновременно. Весь вызов ограничен 120 секундами. Обычный предел ответа MCP 48 KiB сохраняется. Инструмент использует прежний scope `telegram:send`, политику и квоту отправки; каждый элемент альбома расходует одну единицу квоты. Первый контакт и broadcast-канал не поддерживаются. Вызывайте его только при актуальном разрешении пользователя. См. [руководство по политике отправки](SENDING-POLICY.ru.md).

Чтобы включить инструмент, создайте приватный файл API-ключа через менеджер секретов или другой скрытый способ ввода. Не помещайте ключ в исходный код, `.env`, аргументы командной строки или логи. Это должен быть обычный файл без symlink, принадлежащий серверному процессу, с правами `0600` или строже. Для Docker-шаблона подключите файл только для чтения и проверьте, что его владелец совпадает с UID контейнера (`10001`). Затем добавьте к аргументам live-сервера:

    --transcription-provider openai \
    --transcription-key-file /run/assistant/openai_api_key

`--transcription-monthly-seconds` необязательно задаёт лимит секунд аудио на календарный месяц UTC; он сохраняется в существующей базе квот. Значение `0` по умолчанию отключает локальную месячную квоту. Если она включена, секунды резервируются до API-вызова и не возвращаются при ошибке провайдера: это защищает лимит от циклов повторов. `--transcription-max-duration-seconds` может только уменьшить ограничение в пять минут на один файл. Локальная квота секунд отделена от лимита расходов OpenAI на уровне проекта или организации; секунды не задают сумму счёта в валюте. Перед включением решите, какие сообщения можно передавать OpenAI и как безопасно подать ключ. Не используйте реальные аудиозаписи для локальной проверки совместимости.

## 1. Установите проект и проверьте тесты

Нужен Python 3.11 или новее и Linux/macOS с обычным управляющим терминалом для login helper. Для локального preview и переупаковки OGG/Opus также нужны `ffmpeg` и `ffprobe`; Docker image устанавливает их сам. Тесты, использующие PTY, также требуют доступа к `/dev/tty`; ограниченный sandbox может его запрещать. Установите зависимости в виртуальное окружение и тестируйте локально:

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.lock
    .venv/bin/python -m pip install --no-deps --no-build-isolation -e .
    .venv/bin/python -m unittest discover -s tests

Здесь используется пакет `telegram-assistant-mcp`. Не устанавливайте несвязанный PyPI-пакет `telegram-mcp`.

## 2. Создайте отдельную Telegram-сессию

1. В официальном [Telegram Developer Portal](https://my.telegram.org/apps) создайте API application и получите API ID и API hash. Эти значения не публикуйте.
2. Создайте приватные каталоги с правами только для владельца:

       install -d -m 700 private/telegram private/session private/state

3. Запустите интерактивный помощник в обычном терминале:

       PYTHONPATH=src .venv/bin/python -m telegram_assistant.telegram_login \
         --config-dir "$PWD/private/telegram" \
         --session-dir "$PWD/private/session"

4. Введите API ID, hash и номер телефона только в скрытые запросы терминала. Когда помощник попросит подтверждение `SEND`, продолжайте только если вы сами начали этот вход. Введите одноразовый код и, если нужно, пароль двухэтапной проверки. Они не сохраняются. Не передавайте команду через pipe или CI.
5. Успешный вход создаёт `telegram.json` и файл сессии. Оба являются секретами; оставьте им режим `0600`, каталогу сессии — `0700`. Не добавляйте каталог `private/` в Git и не копируйте сессию в тикеты/логи.

Запуск helper — единственный шаг этой инструкции, который выполняет Telegram login. Запуск MCP и его OAuth discovery не должны делать Telegram RPC до первого авторизованного чтения.

## 3. Настройте OAuth API в Auth0

Создайте Custom API для MCP и запишите его Identifier, например `https://telegram-mcp.example.net/mcp`. Значение должно совпадать с адресом MCP resource; это же значение сервер проверяет в audience access token.

В этом подробном примере используется Auth0. Настройки авторизации сервера задаются через issuer, resource и JWKS; использовать другой OAuth-провайдер можно только после проверки совместимости с этими настройками.

Включите подпись RS256 и определите только permission `telegram:read`. Для read-only подключения не создавайте и не назначайте `telegram:send`. Если нужен refresh token, включите у API Allow Offline Access и разрешите приложению запрашивать `offline_access`; выдавайте только необходимые scopes. Auth0 описывает Identifier и профиль подписи в [настройках API](https://auth0.com/docs/get-started/apis/api-settings). Для refresh token нужны `offline_access` и включённый Allow Offline Access; см. [официальную инструкцию Auth0](https://auth0.com/docs/secure/tokens/refresh-tokens).

Заполните `config/auth.example.json`, сохраните копию как `private/auth.json` и задайте режим `0600`:

- `issuer` — точный HTTPS issuer Auth0, обязательно с завершающим `/`;
- `resource` — Identifier API с суффиксом `/mcp`, как он задан серверу;
- `jwks_url` — issuer + `.well-known/jwks.json`;
- `allowed_subjects` — ровно тот Auth0 `sub`, которому разрешено подключать этот личный аккаунт. Это не client ID и не email.

Скопируйте шаблон в приватную папку и отредактируйте его локально:

    cp config/auth.example.json private/auth.json
    cp config/policy.example.json private/policy.json
    chmod 600 private/auth.json private/policy.json private/telegram/telegram.json private/session/assistant.session

В публичном файле оставьте только фиктивные значения. Не помещайте client secret, refresh token или API hash в Git, environment, командную строку или чат.

## 4. Создайте подключение ChatGPT

Доступность добавления собственного MCP зависит от тарифа ChatGPT, региона, аккаунта и политики рабочего пространства. Проверьте, что именно доступно в вашем аккаунте и в [актуальной справке OpenAI](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt); не считайте, что все тарифы дают одинаковые возможности.

Для ChatGPT Web нужен remote MCP endpoint с публичным HTTPS. В интерфейсе создания MCP connector задайте URL сервера, оканчивающийся на `/mcp`, и выберите OAuth. Настройте публичный OAuth client, поддерживающий Authorization Code + PKCE S256. Публичному клиенту не требуется и не следует выдавать client secret.

Для приложения включите grant types Authorization Code и Refresh Token (если нужно автообновление). Публичный client использует token endpoint authentication method `none` и PKCE S256. Если Auth0 отмечает клиент как third-party, назначьте ему user-delegated client grant только на `telegram:read` для вашей API; завершите пользовательский consent. Правила описаны в [документации Auth0 для third-party clients](https://auth0.com/docs/get-started/applications/third-party-applications/security-controls).

ChatGPT передаёт параметр `resource`. В Auth0 он должен соответствовать API Identifier; для обработки `resource` вместо `audience` включите Resource Parameter Compatibility Profile в режиме compatibility в вашем отдельном tenant. Этот параметр описан в [Auth0 PKCE authorize](https://auth0.com/docs/api/authentication/authorization-code-flow-with-pkce/authorize-with-pkce). Сервер проверяет конечный `aud`, поэтому ID token или access token для другой API не подойдут.

Метод регистрации клиента выбирайте по фактическим metadata провайдера: заранее зарегистрированный public client, DCR или CIMD. Если интерфейс ChatGPT выдаёт готовый client ID, используйте его точно; если он выбирает CIMD/DCR, настройте реально поддерживаемый режим Auth0. Не подставляйте случайный client ID.

Скопируйте redirect/callback URL, который ChatGPT показывает для этого connector, без изменений, в список callback URLs OAuth приложения Auth0. ChatGPT использует стабильный callback `https://chatgpt.com/connector_platform_oauth_redirect`, если конфигурация authorization server и connector допускает этот режим. В других случаях URL содержит callback ID; зарегистрируйте именно URI из интерфейса, а не собирайте его вручную. Актуальные правила описаны в [официальном руководстве OpenAI по OAuth для MCP](https://developers.openai.com/plugins/build/auth).

Проверьте, что запрос содержит `telegram:read`, а при необходимости автоматического обновления токена — также `offline_access`. Точный scopes list зависит от настройки connector и Auth0; `telegram:send` не добавляйте. API Identifier должен совпадать с ресурсом, а access token — содержать `telegram:read` и ожидаемый audience. Сначала подключите тестовый профиль, который указан в `allowed_subjects`.

## 5. Запустите локально

Скопируйте `config/policy.example.json` в `private/policy.json`; оставьте пустой список grants. Убедитесь, что `private/auth.json`, `private/telegram/telegram.json` и `private/policy.json` имеют режим `0600`, а каталоги приватных данных — `0700`.

Запуск на компьютере привязывается только к `127.0.0.1:8876`:

    PYTHONPATH=src .venv/bin/python -m telegram_assistant.server \
      --read-only \
      --auth-config "$PWD/private/auth.json" \
      --telegram-config "$PWD/private/telegram/telegram.json" \
      --policy "$PWD/private/policy.json" \
      --runtime-dir "$PWD/private/state"

Локальный HTTP-клиент должен отправлять Host `127.0.0.1:8876`; этот host разрешён сервером. Подключайте URL `http://127.0.0.1:8876/mcp` через локальный MCP-клиент, поддерживающий HTTP OAuth. ChatGPT Web не сможет обратиться к loopback адресу. Для локального Codex можно добавить HTTP server командой:

    codex mcp add telegram-assistant --url http://127.0.0.1:8876/mcp --oauth-client-id YOUR_PUBLIC_CLIENT_ID
    codex mcp login telegram-assistant

Для локального клиента зарегистрируйте callback, который покажет Codex: он отличается от callback ChatGPT Web и может содержать server-specific suffix. Не копируйте для него callback из веб-интерфейса. Параметры описаны в [официальной документации Codex MCP](https://developers.openai.com/codex/mcp). Этот сервер предоставляет Streamable HTTP, stdio transport у него нет.

## 6. Docker и TLS

Файл `deploy/compose.example.yaml` — локальная Linux-ориентированная заготовка. Он привязывает порт только к `127.0.0.1`, запускает непривилегированного пользователя, использует read-only root filesystem и монтирует конфигурацию read-only. Каталог сессии и state остаются отдельными writable mounts. Перед контейнерным запуском укажите в telegram.json путь внутри контейнера `/sessions/assistant.session` (локальный helper сохраняет абсолютный путь хоста). В Linux назначьте приватным файлам и каталогам владельца UID/GID `10001`, потому что контейнер проверяет владельца файлов.

Для локального запуска без Docker файлы должны принадлежать вашему пользователю. Для Linux-контейнера назначьте UID/GID 10001 только приватным файлам и mounts этого проекта; например:

    sudo chown -R 10001:10001 private/telegram private/session private/state
    sudo chown 10001:10001 private/auth.json private/policy.json

Запуск из каталога `deploy`:

    docker compose -f compose.example.yaml up --build

Для удалённого ChatGPT connector нужен публичный HTTPS reverse proxy. Шаблон `deploy/Caddyfile.example` содержит только вымышленный домен: замените его вашим DNS-именем, совпадающим с `resource` в auth.json. Прокси и assistant должны находиться в одной выделенной сети; `assistant:8876` — имя backend в ней. Удалите loopback ports mapping из серверного Compose при работе через эту сеть. Завершайте TLS на прокси, держите backend в отдельной приватной Docker-сети без опубликованного backend-порта и проксируйте только `/mcp` и `/.well-known/oauth-protected-resource/mcp`. Не логируйте тела запросов, Authorization headers или query parameters; отключите body dumps. TLS и ingress настраиваются для вашей инфраструктуры отдельно: локальный Compose пример не предназначен для прямой публикации в интернет.

Перед deployment зафиксируйте проверенный digest базового image, просмотрите зависимости и настройте мониторинг так, чтобы он не сохранял токены, содержимое сообщений и параметры Telegram RPC.

## 7. Первый вызов и cooldown

После запуска выдержите минимум 60 секунд startup grace; сохранённый cooldown может быть дольше. После подключения OAuth сначала запросите одну строку каталога, например `list_dialogs(limit=1)`. Пагинация возвращает cursor для следующей ограниченной страницы; не запускайте параллельные страницы. При `telegram_rate_limited`/`retry_after_seconds` остановитесь и дождитесь указанного срока. Не делайте циклы повторов и не запускайте повторный вход из-за rate limit.

Ошибки разделены по слоям:

- HTTP `401` и `WWW-Authenticate` — OAuth token, audience, issuer, scope или owner allowlist;
- `telegram_unavailable` — Telegram transport/session ошибка, если не получен типизированный rate-limit ответ;
- `telegram_rate_limited` — typed Telegram FloodWait; соблюдайте `retry_after_seconds`;
- ошибка файлов или session lock — локальные права/конкурирующий процесс, не OAuth reconnect.

Текст одного сообщения ограничен 2000 символами; `text_truncated=true` обозначает сокращение. JSON-ответ ограничен 48 KiB, кроме нативного MCP image response инструмента `view_photo`, у которого JSON envelope ограничен 512 KiB. Сервис не выполняет полный экспорт истории.

Публичный metadata route не подтверждает, что Telegram сессия работает. Актуальность пользовательского канала также проверяется отдельно: по умолчанию broadcast-каналы фильтруются.

## Metadata-only bootstrap до Telegram login

Для проверки OAuth discovery есть отдельный режим без Telegram-конфига и без сессии. Скопируйте bootstrap-шаблон, укажите настоящий issuer/resource и задайте права:

    cp config/bootstrap.example.json private/bootstrap.json
    chmod 600 private/bootstrap.json
    .venv/bin/python -m telegram_assistant.server \
      --mode bootstrap --bootstrap-config "$PWD/private/bootstrap.json"

Он отдаёт metadata и возвращает 401 на любой `/mcp` запрос, даже с bearer. Инструменты отсутствуют. Это способ получить точные callback/client metadata до настройки разрешений; это не live reader и не проверка Telegram. Если bootstrap уже работает, сначала согласуйте с пользователем его остановку, прежде чем запускать live режим на том же порту.

## Когда требуется reconnect

OAuth access token и Telegram session — разные учётные данные. Истечение OAuth токена исправляет refresh token, если он был выдан; при отзыве refresh token понадобится повторное OAuth consent. Telegram `session_not_authorized` требует отдельной диагностики сессии. `telegram_rate_limited` не требует login/reconnect. Не запускайте одну Telegram session одновременно на нескольких компьютерах: локальный session lock защищает только один host.

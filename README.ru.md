# hookbench

[English](README.md) | [Русский](README.ru.md)

Скилл и CLI, разделяющие три способа, которыми ломаются вебхук-интеграции: обработчик не вызывается (экспозиция), подпись не сходится (секрет/сериализация), обработчик ошибается (логика).

```text
$ hookbench receive --port 8080 --secret-file secret.txt --out captured.ndjson
[1] /hook (signature_valid=True) body: {"event": "payment.succeeded", "id": 7}

$ hookbench replay captured.ndjson --url http://localhost:9000/handler --secret-file secret.txt
  #1 /hook -> 200  {"received": true}
```

Реальные пейлоады становятся фикстурами; фикстуры — тестовым набором интеграции; реплей переподписывает свежим таймстампом, чтобы твой собственный реплей не съедался защитой от replay. Проверка подписи — constant-time, схемы raw-payload и timestamped (в стиле Stripe), устаревший таймстамп помечается как возможный replay даже при валидной подписи.

## Что в репозитории

- **[skills/webhook-integration-testing](skills/webhook-integration-testing)** — захват → проверка → реплей, ловушка сериализации (подпись покрывает точные байты; прокси с pretty-print ломает её), отличия схем вендоров и граница: не подделывать подпись для чужого секрета.
- **tools/hookbench** — CLI ([README](tools/hookbench/README.md)): `receive` / `verify` / `replay`, только stdlib (http.server + urllib + hmac).

## Установка

```bash
pip install hookbench
npx skills add juzorei/hookbench
```

## Ещё из портфеля

Один из серии прицельных наборов «скилл + CLI» одного автора:

- [harrecon](https://github.com/juzorei/harrecon) — захвати API-часть той же интеграции
- [ci-autopsy](https://github.com/juzorei/ci-autopsy) — обработчики вебхуков в CI падают как всё остальное
- [loglens](https://github.com/juzorei/loglens) — что лог доставки говорит, когда никто не смотрит

Остальные — в [профиле juzorei](https://github.com/juzorei?tab=repositories).

## Рамки

Захват и реплей вебхуков интеграций, которыми ты владеешь или уполномочен тестировать.

Лицензия MIT.

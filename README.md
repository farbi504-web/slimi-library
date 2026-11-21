# مكتبة سليمي | Librairie Slimi

متجر ومنصة إدارة لمكتبة سليمي (عطبة، تيبازة): واجهة متجر بالعربية والفرنسية، ولوحة تحكم للطلبات والمنتجات والاشتراكات والموظفين.

Online store + admin dashboard for Librairie Slimi (Attatba, Tipaza). Arabic (RTL) and French.

## Run

Requires Node.js >= 22.13. No npm dependencies (uses built-in `node:sqlite`).

```
OWNER_PASSWORD='choose-a-strong-password' node server.js
```

Store: `http://localhost:3000/` · Admin: `http://localhost:3000/admin` (user `owner`).

## Environment variables

| Name | Purpose |
|---|---|
| `PORT` | Port (default 3000) |
| `DATA_DIR` | Where the SQLite database lives (default `./data`) |
| `OWNER_PASSWORD` | Owner password on first start (random one is printed if unset). Change it after first login |
| `PUBLIC_URL` | Public site URL (used for payment return links) |
| `CHARGILY_SECRET_KEY`, `CHARGILY_MODE` | Chargily Pay (`test` or `live`) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram order notifications |

Never commit the database (`data/`) or any keys.

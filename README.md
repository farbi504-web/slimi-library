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
| `TRUST_PROXY` | Set to `true` only when deployed behind a trusted reverse proxy that overwrites `X-Forwarded-For`; otherwise leave unset |
| `OWNER_PASSWORD` | Owner password on first start (random one is printed if unset). Change it after first login |
| `PUBLIC_URL` | Public site URL (used for payment return links) |
| `CHARGILY_SECRET_KEY`, `CHARGILY_MODE` | Chargily Pay (`test` or `live`) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram order notifications |

Never commit the database (`data/`) or any keys.


## Security notes

- Keep `data/`, database files, and all `.env` files out of Git. The repository includes a `.gitignore` for these paths.
- Use a strong `OWNER_PASSWORD` in production and serve the site over HTTPS.
- Set `TRUST_PROXY=true` only when your hosting proxy sanitizes forwarded client-IP headers; otherwise the application uses the direct socket address for rate limiting.
- Run `npm run check` before deploying to validate the server JavaScript syntax.

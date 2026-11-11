# OBRS Helper

A small web app for authorised registry staff to use OBRS operations without Postman. The Express server proxies only the supported routes; the browser never calls the OBRS API directly.

## Requirements

- Node.js 18 or newer
- Access to the URSB LAN/VPN and an authorised OBRS bearer token

## Setup

1. Copy `.env.example` to `config/.env` (or copy `config/.env.example` there).
2. Set `OBRS_BASE_URL=https://obrs-api.ursb.go.ug` in `config/.env`. `PORT` defaults to `3000`, and `HOST` defaults to `127.0.0.1`.
3. Run from the project directory:

   ```sh
   npm install && npm start
   ```

4. Open <http://localhost:3000>, paste your bearer token for EDMS list and unlock actions. Document viewing does not send a bearer token.

Local sign-in is optional unless `DATABASE_URL` is set. To develop the account-management feature locally, configure a PostgreSQL database URL, an `APP_SESSION_SECRET` of at least 32 characters, and a bootstrap username/password. The first admin password must be at least 12 characters.

The unlock-file request uses **POST**, as confirmed for this installation. Its method is defined by the single `UNLOCK_METHOD` constant in `server.js`.

## Render deployment

The repository includes a Render Blueprint in `render.yaml`, which references the existing Render Postgres resource named `obrs`. It uses Render's internal connection URL because the database and app are in the same region; Render injects this URL into the service without exposing the database password. The app creates and uses only its dedicated `obrs_helper` schema; the database instance is still shared with its existing project.

For an existing deployment, sync the updated Blueprint from the Render dashboard and set `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` directly in Render; use a unique password of at least 12 characters. Render generates `APP_SESSION_SECRET`. The first administrator is created only when the accounts table is empty; changing bootstrap environment values later does not overwrite existing accounts.

**Free Render Postgres expires 30 days after creation, and its data (including all user accounts) is deleted.** This is suitable only for a temporary trial. Upgrade the database before expiry if accounts must persist. Render also spins down free web services when idle.

The Render service requires approved private connectivity to the URSB network to reach OBRS. Do not deploy it unless that network path and URSB LAN/VPN access restrictions are configured. The app requires sign-in for every proxy API route in production, rate-limits sign-in attempts, and sets an HTTP-only, secure, SameSite session cookie.

The bootstrap administrator can create user accounts, reset passwords, deactivate/reactivate accounts, and delete user accounts. There is no public self-sign-up. Only the bootstrap administrator has the admin role; admin accounts cannot be deactivated or deleted through the interface.

## Security notes

- Use only on the URSB LAN/VPN with your own authorised token.
- The token is kept in the current tab's `sessionStorage` so page reloads do not require re-entry. It is sent in an `Authorization: Bearer` header only for EDMS-list and unlock operations; document-viewing requests do not send it. Clear removes the saved token, and a 401 response clears it so a replacement can be entered.
- The proxy has five fixed API routes and does not accept arbitrary upstream URLs.
- In account mode, passwords are hashed with bcrypt; password resets and deactivation revoke the affected user's existing sessions. Account sessions are checked against the database on every protected API request.
- `APP_SESSION_SECRET` signs the HTTP-only session cookie and must be at least 32 characters. `BOOTSTRAP_ADMIN_PASSWORD` is only used to create the first administrator in an empty database.
- The app account password is separate from each user's OBRS bearer token. The bearer token is used only for EDMS listing and unlock.
- Payment confirmation uses `GET /billing/transaction/query?reference=...`; the parameter name is defined by `PAYMENT_REFERENCE_QUERY_PARAM` in `server.js`.
- Document viewers include a direct OBRS link for opening or sharing outside the app; recipients still need network access to the OBRS service.
- The app does not log request headers or request values. Use an appropriately protected local machine and network.
- For LAN/VPN deployment, set `HOST=0.0.0.0` only on a server protected by a firewall or reverse proxy that limits access to URSB LAN/VPN users. Do not expose the app directly to the public internet.

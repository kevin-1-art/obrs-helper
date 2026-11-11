# OBRS Helper

A small web app for authorised registry staff to use OBRS operations without Postman. The Express server proxies only the supported routes; the browser never calls the OBRS API directly.

## Requirements

- Node.js 18 or newer
- Access to the URSB LAN/VPN and an authorised OBRS bearer token

## Setup

1. Copy `.env.example` to `config/.env` (or copy `config/.env.example` there).
2. Set `OBRS_BASE_URL=https://obrs-api.ursb.go.ug` in `config/.env`. Optionally set `PORT` (defaults to `3000`).
3. Run from the project directory:

   ```sh
   npm install && npm start
   ```

4. Open <http://localhost:3000>, paste your bearer token for EDMS list and unlock actions. Document viewing does not send a bearer token.

The unlock-file request uses **POST**, as confirmed for this installation. Its method is defined by the single `UNLOCK_METHOD` constant in `server.js`.

## Security notes

- Use only on the URSB LAN/VPN with your own authorised token.
- The token is kept in the current tab's `sessionStorage` so page reloads do not require re-entry. It is sent in an `Authorization: Bearer` header only for EDMS-list and unlock operations; document-viewing requests do not send it. Clear removes the saved token, and a 401 response clears it so a replacement can be entered.
- The proxy has five fixed API routes and does not accept arbitrary upstream URLs.
- Payment confirmation uses `GET /billing/transaction/query?reference=...`; the parameter name is defined by `PAYMENT_REFERENCE_QUERY_PARAM` in `server.js`.
- Document viewers include a direct OBRS link for opening or sharing outside the app; recipients still need network access to the OBRS service.
- The app does not log request headers or request values. Use an appropriately protected local machine and network.

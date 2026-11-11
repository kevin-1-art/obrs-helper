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

The unlock-file request uses **POST**, as confirmed for this installation. Its method is defined by the single `UNLOCK_METHOD` constant in `server.js`.

## Render deployment

The repository includes a Render Blueprint in `render.yaml`. In Render, create a new Blueprint from this repository and set `APP_ACCESS_PASSWORD` to a strong shared app password. Render generates `APP_SESSION_SECRET`. Share the app password with authorised users through an approved channel; it is separate from each user's OBRS bearer token.

The Render service requires approved private connectivity to the URSB network to reach OBRS. Do not deploy it unless that network path and URSB LAN/VPN access restrictions are configured. The app requires sign-in for every proxy API route in production, rate-limits sign-in attempts, and sets an HTTP-only, secure, SameSite session cookie.

## Security notes

- Use only on the URSB LAN/VPN with your own authorised token.
- The token is kept in the current tab's `sessionStorage` so page reloads do not require re-entry. It is sent in an `Authorization: Bearer` header only for EDMS-list and unlock operations; document-viewing requests do not send it. Clear removes the saved token, and a 401 response clears it so a replacement can be entered.
- The proxy has five fixed API routes and does not accept arbitrary upstream URLs.
- In production, `APP_ACCESS_PASSWORD` and `APP_SESSION_SECRET` are required. The app password protects all API routes, including document and payment lookup; it is not the OBRS bearer token.
- Payment confirmation uses `GET /billing/transaction/query?reference=...`; the parameter name is defined by `PAYMENT_REFERENCE_QUERY_PARAM` in `server.js`.
- Document viewers include a direct OBRS link for opening or sharing outside the app; recipients still need network access to the OBRS service.
- The app does not log request headers or request values. Use an appropriately protected local machine and network.
- For LAN/VPN deployment, set `HOST=0.0.0.0` only on a server protected by a firewall or reverse proxy that limits access to URSB LAN/VPN users. Do not expose the app directly to the public internet.

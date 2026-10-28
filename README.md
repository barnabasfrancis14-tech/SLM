# Student Life Manager — Cloud Upgrade

This project keeps the existing Student Life Manager interface and adds a Node.js/Express API, MongoDB persistence, server-side password hashing, HttpOnly session cookies, analytics, calendar export, scheduled email reminders, and installable PWA support.

## Requirements
- Node.js 20+
- MongoDB (local or MongoDB Atlas)
- Optional SMTP account for email reminders

## Run locally
1. Install Node.js and MongoDB, or create a MongoDB Atlas database.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `SESSION_SECRET`, and `APP_ORIGIN`.
3. Use a long random secret, e.g. `openssl rand -base64 48`.
4. Run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000` (do not open `public/index.html` directly).

## Included API
- `POST /api/auth/register` — create account
- `POST /api/auth/login` — sign in
- `POST /api/auth/logout` — destroy session
- `GET /api/auth/me` — current session user
- `GET /api/data` / `PUT /api/data` — cloud data sync
- `GET /api/analytics` — dashboard analytics summary
- `GET /api/calendar.ics` — calendar file export

## Important integration note
The original UI is retained. The API is ready, but client-side authentication and data syncing must be connected to it before treating this as a production deployment. The HTML currently contains its original local-storage authentication and persistence. The next step is to replace those functions with API calls; the local password hashing in the original frontend is not secure authentication. This scaffold intentionally does not claim that those original flows have already been migrated.

## Notifications
- The existing interface's browser-side reminders remain available while the app is open.
- Scheduled email reminders run daily at 08:00 server time when SMTP variables are configured and a user's email reminders setting is enabled.
- Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env` to enable email.

## PWA / mobile
The web app has a manifest and service worker for installable, mobile-friendly PWA support. Serve it over HTTPS in production for installation and browser notification features. This is not a native Android/iOS app.

## Security checklist before deployment
- Use HTTPS and `NODE_ENV=production`.
- Use a unique, strong `SESSION_SECRET` and a private MongoDB user with least privilege.
- Configure `APP_ORIGIN` to the exact deployed origin.
- Configure SMTP with an app-specific credential.
- Add automated tests, account recovery/email verification, CSRF protection appropriate to the deployment, audit logging, backups, and monitoring before public launch.

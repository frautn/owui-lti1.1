# Django LTI 1.1 External Tool Middleware for OpenWebUI

v0.1

Minimal Django project that acts as Middleware, accepts an LTI 1.1 launch from Moodle and opens OpenWebUI chat inside an iframe.


## Prerequisites

You need an Open WebUI server. 

Check `https://github.com/frautn/open-webui-chat-simplified/pkgs/container/open-webui-chat-simplified` for a custom docker images that shows a simplified chat page, stripped of possible unwanted features.

## Install

```bash
pip install django python-dotenv
```

## Environment

Copy `.env.example` to `.env` and set values.

Required values:

- `DJANGO_SECRET_KEY`
- `MOODLE_CONSUMER_KEY` (default is `moodle_key`)
- `MOODLE_SHARED_SECRET`
- `OPENWEBUI_URL`:
    - when developing with local server, use example `http://localhost:3000`
    - production: `https://example.webui.com`
    - It's important to use the actual Open WebUI url (the one that users can log in), and not the url used for the Django Api middleware.

Optional values for OpenWebUI auto sign-in from LTI launch:

- `OPENWEBUI_TRUSTED_EMAIL_HEADER` (for example `X-Forwarded-Email`)
- `OPENWEBUI_TRUSTED_NAME_HEADER` (for example `X-Forwarded-Name`)
- `OPENWEBUI_TRUSTED_ROLE_HEADER` (for example `X-Forwarded-Role`)
- `OPENWEBUI_AUTOLOGIN_PASSWORD` (fallback password mode when trusted-header mode is not enabled)

Notes:

- Best practice is trusted-header mode in OpenWebUI, so each LTI user gets their own OpenWebUI account automatically.
- Cookie handoff only works when Django and OpenWebUI are on the same host name (ports can differ).

Optional production values for reverse proxy deployments:

- `LTI_TRUST_PROXY_HEADERS` (default `True`)
- `LTI_EXTERNAL_LAUNCH_URL` (for example `https://lti.example.edu/lti/launch/`)

Use `LTI_EXTERNAL_LAUNCH_URL` when Moodle signs launches against a public URL that differs from the internal Django URL seen by the app.

## Run

```bash
python manage.py migrate
python manage.py runserver <port number>
```

You might need to set the port number if you are running Moodle locally too. Default is 8000.

## Endpoints

- Launch URL: `/lti/launch/`
- Config URL (cartridge XML): `/lti/config.xml`
- Chat page (session-backed): `/lti/chat/`
- Health check: `/lti/health/`

## Moodle Configuration (LTI 1.1)

In Moodle external tool settings:

- Tool URL: your Django launch URL, for example `https://your-host/lti/launch/`
- Consumer key: `MOODLE_CONSUMER_KEY`
- Shared secret: `MOODLE_SHARED_SECRET`

You can also import the tool using the cartridge config URL: `https://your-host/lti/config.xml`.

## Tested in these Moodle versions
  - 5.02
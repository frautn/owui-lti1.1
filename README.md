# Django LTI 1.1 External Tool for OpenWebUI

v0.1

Minimal Django project that accepts an LTI 1.1 launch from Moodle and opens OpenWebUI chat inside an iframe.


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
- `OPENWEBUI_URL` (for example `http://localhost:3000`)

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
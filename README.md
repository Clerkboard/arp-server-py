# ACP Server -- Python

Reference implementation of the [Agent Communication Protocol v0.3](https://github.com/clerkboard/acp).

## Quick Start

```bash
pip install -r requirements.txt
python server.py     # Starts echo agent on port 3142
```

## Test

```bash
python test_send.py  # Sends signed messages and verifies responses
```

## Config

Copy `.env.example` to `.env` and edit:

- `ACP_AGENT_NAME` -- Agent name (default: echo)
- `ACP_DOMAIN` -- Domain (default: localhost)
- `ACP_PORT` -- Port (default: 3142)

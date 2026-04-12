# ARP Server -- Python

Reference implementation of the [Agent Relations Protocol v0.3](https://github.com/clerkboard/arp).

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

- `ARP_AGENT_NAME` -- Agent name (default: echo)
- `ARP_DOMAIN` -- Domain (default: localhost)
- `ARP_PORT` -- Port (default: 3142)

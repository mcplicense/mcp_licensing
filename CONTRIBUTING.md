# Contributing

Thanks for looking. Bug reports, fixes and documentation improvements are welcome.

## Before you start

* For anything bigger than a small fix, open an issue first so we can agree on the direction.
* Security problems: do **not** open an issue; see [SECURITY.md](SECURITY.md).
* By contributing you agree that your contribution is licensed under the Apache License 2.0, like the rest of
  the project.

## Running the tests

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt   # on Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m pytest -q
```

The suite needs no AWS account: DynamoDB, SSM and the rest run on `moto`, and Cognito is replaced by a
checked stand-in (`tests/fake_cognito.py`). The JavaScript tests in `tests/js/` need Node 18 or later.

To click through the whole website without any AWS account, see "Try it locally" in the README
(`scripts/dev_server.py`).

## Guidelines

* Keep the code in the style of the files around it, including how much it is commented.
* Every behaviour change needs a test; a security property needs a test that pins it.
* Never commit secrets, real account or deployment ids, personal email addresses, or real customer data.
  Use `example.com` and obviously fake ids in tests and docs.
* The website is static and its scripts are loaded as files from the same site (a strict content security
  policy). No inline scripts or styles, no third-party requests, no analytics.
* `sam validate --lint -t template.yml` (and the same for `edge.yml`, `site.yml`, `mail.yml`) must pass.

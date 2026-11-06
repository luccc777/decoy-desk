# Decoy Desk

**Before you run what a stranger sent you, send it to Decoy Desk.**

Decoy Desk checks whether the company or person who sent you a repository or file really exists, then runs what they sent on a disposable decoy machine (gVisor on Vultr). It answers with a plain verdict and the evidence behind it.

Built for the Vultr Agent Rush hackathon, track *Blast Radius Zero*. Work in progress.

## Status

- [x] Vultr VM with Docker and gVisor; containment tests in `infra/gvisor_verify.sh`
- [x] Rules table and engine that decide the verdict color, with tests
- [ ] Sender legitimacy checks and static read
- [ ] Decoy machine for repositories
- [ ] Web app

## How the verdict is decided

One table, [`backend/app/rules/rules_table.yaml`](backend/app/rules/rules_table.yaml), and one pure function, [`engine.py`](backend/app/rules/engine.py), decide the color. Neither touches the network or a language model. The model only extracts claims from a conversation and explains the result.

- **Red:** any hard trigger fires, or the score reaches 50. Examples of hard triggers: the repo read the decoy SSH key, or the file is a program disguised as a PDF.
- **Yellow:** the score is 20 to 49, or fewer than 60% of the checks that apply could be answered. A failed check counts as unknown, never as clear.
- **Green:** anything else. Points that lower the risk, such as a job listed on the official careers board, take off at most 20.

## Run the tests

```bash
cd backend
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

## License

MIT

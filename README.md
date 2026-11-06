# Decoy Desk

**Before you run what a stranger sent you, send it to Decoy Desk.**

Decoy Desk checks whether the company or person who sent you a repository or file really exists, then runs what they sent on a disposable decoy machine (gVisor on Vultr). It answers with a plain verdict and the evidence behind it.

Built for the Vultr Agent Rush hackathon, track *Blast Radius Zero*. Work in progress.

## Status

- [x] Vultr VM with Docker and gVisor; containment tests in `infra/gvisor_verify.sh`
- [x] Rules table and engine that decide the verdict color, with tests
- [x] Sender checks: is the company real, and does the conversation follow a known scam script
- [ ] Static read of repos and files
- [ ] Decoy machine for repositories
- [ ] Web app

## How the verdict is decided

One table, [`backend/app/rules/rules_table.yaml`](backend/app/rules/rules_table.yaml), and one pure function, [`engine.py`](backend/app/rules/engine.py), decide the color. Neither touches the network or a language model. The model only extracts claims from a conversation and explains the result.

- **Red:** any hard trigger fires, or the score reaches 50. Examples of hard triggers: the repo read the decoy SSH key, or the file is a program disguised as a PDF.
- **Yellow:** the score is 20 to 49, or fewer than 60% of the checks that apply could be answered. A failed check counts as unknown, never as clear.
- **Green:** anything else. Points that lower the risk, such as a job listed on the official careers board, take off at most 20.

## Who sent it

Before anything runs, Decoy Desk checks the sender against public records. Every source is free and needs no account:

| Question | Source |
|---|---|
| How old is the company's domain? Was it seized? | RDAP |
| When did the site first appear? | Wayback Machine |
| Can the domain receive email (MX, SPF, DMARC)? | DNS over HTTPS |
| What is the company's real website? | Wikidata, never the sender's word |
| Is the job on the official careers board? | Greenhouse, Lever, Ashby |
| Is the repo on a personal or a brand-new account? Is the GitHub org real? | GitHub API |
| Is a link or email a lookalike of the real domain, or a fake Zoom/Teams link? | Code, no network |
| Did the email pass DMARC for the real domain? | The headers you paste |

A language model (Vultr Serverless Inference) reads the conversation and fills a fixed schema: the claimed company, its claimed age, and signs like "run it on your work laptop before our call". Every signal must come with a quote that the code finds word for word in the text, or it is dropped. The worst patterns are also matched by plain rules, so they don't depend on the model. The model can't set off a hard trigger on its own.

The demo case `backend/fixtures/fake_company_blocknovas` replays a live run against BlockNovas, a front company from a real 2025 fake-recruiter campaign. It comes out red before anything is run: its domain is still under an FBI seizure notice, and it claims 12 years in business on a domain registered in July 2024.

## Run the tests

```bash
cd backend
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

## License

MIT

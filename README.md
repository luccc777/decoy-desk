# Decoy Desk

**Before you run what a stranger sent you, send it to Decoy Desk.**

Decoy Desk checks whether the company or person who sent you a repository or file really exists, then runs what they sent on a disposable decoy machine (gVisor on Vultr). It answers with a plain verdict and the evidence behind it.

Built for the Vultr Agent Rush hackathon, track *Blast Radius Zero*. Work in progress.

## Status

- [x] Vultr VM with Docker and gVisor; containment tests in `infra/gvisor_verify.sh`
- [ ] Rules engine, sender legitimacy checks, static read
- [ ] Decoy machine for repositories
- [ ] Web app

## License

MIT

# Reporting a security problem

If you believe you have found a security flaw in Aska — in the Block format, the protocol, the clients, the relay, the build or the release process — please report it **privately** first, so that a fix can be released before the flaw is public:

- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository. Only the maintainer sees it.
- A report must never contain a real note, key, Key Card, passphrase, receiving seed or relay address. Steps to reproduce, the version (`aska verify` prints it) and the output of `aska doctor` are enough.

What to expect: an acknowledgement, a fix or a written reason why not, and credit in the release notes if you want it. There is no bug bounty.

**Status of the current release.** Aska 1.1.0 has passed the project's own gates and an internal security pre-review (`docs/Aska_Internal_PreReview_Report_v0.1.md`); it has **not** had an independent security audit or a legal review. The Security Review Package (`docs/Aska_Security_Review_Package_v0.1.md`) and the Legal Review Brief (`docs/Aska_Legal_Review_Brief_v0.1.md`) are published so that anyone qualified can conduct one; a report from such a review will be published with the next release.

**Verifying a release** is described in `docs/USER_GUIDE.md`, section 3: get the fingerprint out of band first, then the files; releases are signed with minisign key `79AD6224AFF176C9` (`release/aska-release.pub`). Never install an update because software told you one exists.

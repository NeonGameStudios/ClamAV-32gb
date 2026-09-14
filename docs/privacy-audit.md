# Privacy audit

Audit scope: the current working tree, excluding Git's internal object
database and history.

## Redacted from project documentation

- local and remote filesystem paths containing user or workstation names;
- remote login usernames and authentication profile names;
- private runner addresses; and
- opaque remote request and transfer identifiers.

The redactions apply to Markdown and TSV evidence files. They do not change
scanner behavior, test fixtures, or source code semantics.

## Deliberately retained

- upstream contributor names, email addresses, copyright notices, and license
  contacts required for attribution and legal notices;
- official ClamAV/Cisco security and community contact addresses; and
- generic example addresses and protocol test data used by the existing test
  suite.

A targeted scan found no obvious private keys, API tokens, access tokens, or
  credential assignments in the current working tree. This is not a substitute
  for reviewing any private artifacts before publication.

Git history was not rewritten. Previously pushed commits may still contain
older environment-specific strings; removing those requires a separately
coordinated history rewrite because it changes published commit identities.

# Security policy

## Reporting a problem

Please don't open a public issue for a security problem. Report it privately through GitHub instead:

https://github.com/Ghost0308/safetape/security/advisories/new

That's the same as opening the **Security** tab of this repo and clicking **Report a vulnerability**. Only you and I can see the report.

I'll reply within 7 days. If the report checks out, I'll work on a fix and aim to release it within 90 days, usually much sooner. We'll agree on a disclosure date together. Once a fixed version is out I'll publish a security advisory, and I'll credit you in it and in the release notes if you'd like that.

## Supported versions

safetape is still pre 1.0, so only the latest release gets security fixes.

## What I treat as a vulnerability

- A secret ends up in a cassette file when safetape should have stopped it, in a case the docs say is covered
- A secret safetape should have masked shows up in its own error messages or in a pytest failure report
- Loading a cassette through safetape can run code or read files it shouldn't
- Something in the build or release process that could let someone ship a tampered package

A secret format that safetape doesn't recognise yet is useful to know about too, but that can go in a normal issue. Just don't paste a real key, a made-up one in the same format is enough.

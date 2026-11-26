# Security policy

## Reporting a problem

Please don't open a public issue for a security problem. Use GitHub's private reporting instead: open the **Security** tab of this repo and click **Report a vulnerability**.

I'll reply within 7 days. If the report checks out I'll work on a fix, publish an advisory once a fixed version is out, and credit you in the release notes if you'd like that.

## Supported versions

safetape is still pre 1.0, so only the latest release gets security fixes.

## What I treat as a vulnerability

- A secret ends up in a cassette file when safetape should have stopped it, in a case the docs say is covered
- Loading a cassette through safetape can run code or read files it shouldn't
- Something in the build or release process that could let someone ship a tampered package

A secret format that safetape doesn't recognise yet is useful to know about too, but that can go in a normal issue. Just don't paste a real key, a made-up one in the same format is enough.

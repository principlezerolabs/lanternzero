# Releasing

A release is a version tag on `main`. The tag publishes the self-hosting
kit's signed images (`.github/workflows/images.yml`); the kit then pins
their digests. The Rust crates aren't published (`publish = false`).

Updates are opt-in for self-hosters, because the server holds viewing keys
for anyone who turns on scanning (`deploy/DESIGN.md`, "Releases"). So
every release says whether it touches key handling.

## 1. Before tagging

- CI is green on the commit to tag, including the `Zaino NU7 fallback`
  workflow while that fallback exists.
- Pick the version. Before 1.0, minor versions (`v0.2.0`) may break the
  API and the kit; patch versions (`v0.2.1`) don't.
- List what changed since the last release, and the changes to code that
  handles keys, tokens, or their storage:

  ```sh
  prev=$(git describe --tags --abbrev=0)
  git log --oneline "$prev"..HEAD
  git diff --stat "$prev"..HEAD -- \
    server/src/scanner server/src/viewkey.rs server/src/keys.rs \
    server/src/ohttp_keys.rs server/src/store server/src/hardening.rs \
    server/src/issuer.rs crates/lz-proto/src client/core/src
  ```

  For the first release, there is no `$prev`: say so, and describe the
  release as a whole.

## 2. Release notes

Write them before tagging, in this shape:

```markdown
## Lantern Zero vX.Y.Z

**Touches key handling: yes / no.** <If yes: what changed, in a sentence
or two, and whether self-hosters should update soon.>

### Changes
- ...

### Images
<filled in after step 4>
```

## 3. Tag

```sh
git tag -a vX.Y.Z -m "Lantern Zero vX.Y.Z"   # -s instead of -a to sign it, with a key set up
git push origin vX.Y.Z
```

The push starts the Images workflow. Its run summary lists both images'
digests. The images are tagged `X.Y.Z` and `sha-<commit>`, never `latest`.

## 4. Verify

With cosign 3 or newer, for both digests from the run summary:

```sh
cosign verify ghcr.io/principlezerolabs/lantern-zero-server@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/principlezerolabs/lanternzero/\.github/workflows/images\.yml@refs/tags/v'
docker buildx imagetools inspect ghcr.io/principlezerolabs/lantern-zero-server@sha256:<digest>
```

`imagetools inspect` should list `linux/amd64` and `linux/arm64`. Do the
same for `lantern-zero-tor`. Then add both full `…@sha256:` references, and
the verify command, to the release notes' "Images" section.

The packages must be public for self-hosters to pull them (the
organization's package settings on GitHub; once per package).

## 5. Publish the notes, then pin the kit

```sh
gh release create vX.Y.Z --title "Lantern Zero vX.Y.Z" --notes-file notes.md
```

Then, in one commit on `main`, make the new digests the kit's defaults:
the `${LZ_SERVER_IMAGE:-…}` and `${LZ_TOR_IMAGE:-…}` defaults in
`deploy/compose.yaml`, and the examples in `deploy/.env.example`. Run
`deploy/smoke-test.sh`; it builds locally, so also start the kit once with
the pinned images.

The first time, this also changes the kit from building to pulling:
`deploy/README.md`'s "Set up" uses `docker compose pull` and `up
--no-build`, local builds set `LZ_SERVER_IMAGE=lantern-zero/server:local`
and `LZ_TOR_IMAGE=lantern-zero/tor:local`, and so do `smoke-test.sh` and
the skill. A digest can't be a build tag, so a pinned default can't be
built over.

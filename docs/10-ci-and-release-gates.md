# CI, Release, and Review Gates

## Deterministic merge checks

Pull requests run two deterministic workflows:

- **windows-ci** tests the root cleanup tool on Windows Server 2022 and 2025,
  under Windows PowerShell 5.1 and pwsh where the test applies.
- **gui-revision-ci** runs GUI static, Pester, WPF-smoke, headless-smoke,
  malformed-config, and portable-package checks. Once this workflow is on
  `main` it also runs after merges to `main`, in addition to every pull request
  and GUI-branch push.

Branch protection for `main` currently requires the two `windows-tests` matrix
legs, which are the contexts `main` can produce today. `gui-revision-ci`'s
`Linux static checks` and `Windows dynamic (windows-2022/2025)` contexts must be
added to the required list in the same change that first lands
`gui-revision-ci.yml` on `main`; requesting them earlier leaves them
permanently "Expected - waiting for status to be reported" and blocks every
merge. The scanner probe and AI review are never merge gates because they depend
on an external vendor and an LLM endpoint respectively.

## Portable release process

Creating and pushing a `v*` tag starts **Release portable package**. It:

1. builds the portable ZIP on Windows Server 2022;
2. checks the ZIP sidecar hash, archive layout, and every `SHA256SUMS.txt`
   member hash;
3. downloads that exact artifact on Windows Server 2025 and checks it again;
4. publishes only after both checks passed, by uploading the ZIP and sidecar to
   the matching GitHub Release; and
5. downloads the published asset and compares its SHA-256 with the built ZIP.

A failed build, integrity check, or cross-runner extraction stops publication
before anything is uploaded. Step 5 runs after upload, so a corrupt upload fails
the run but leaves the asset in place: re-run the workflow after investigating,
because `gh release upload --clobber` replaces the asset.

## OpenCodeReview setup

The `OpenCodeReview` workflow is intentionally disabled until its LLM endpoint
is configured. This prevents an unconfigured reviewer from failing every PR.

In **Settings -> Secrets and variables -> Actions**, configure:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `OCR_LLM_URL` | OpenAI-compatible or Anthropic review endpoint |
| Secret | `OCR_LLM_AUTH_TOKEN` | Token for that endpoint |
| Variable | `OCR_LLM_MODEL` | Review model identifier |
| Variable | `OCR_LLM_USE_ANTHROPIC` | `true` for Anthropic protocol; otherwise `false` (the workflow defaults an unset variable to `false`, because the action treats an empty value as Anthropic) |
| Variable | `OCR_ENABLED` | Set to `true` only after all values above exist |

When enabled, OCR reviews non-draft PRs, posts a sticky summary, and avoids
posting overlapping inline comments from earlier runs. It reads the trusted base
and PR diff only; it does not execute PR code. OCR findings are advisory and do
not replace deterministic CI or human review.

## Scanner launch probe

`scanner-launch-probe` is a scheduled/manual diagnostic for hosted Windows
launch behavior of vendor scanners. Vendor download blocks and scanner GUI
behavior are outside repository control, so its result is evidence for
maintenance—not a required merge check. Investigate a failure before claiming a
scanner-launch regression.

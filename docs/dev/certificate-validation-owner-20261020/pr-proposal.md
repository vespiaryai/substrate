# Proposed source repair

Proposed title is `fix(ate-setup): scope native certificate S3 validation`.
The selected source repair and focused tests are complete. Mandatory full verification and independent review remain pending.
Root owns publication to the external fork and separate recovery of its exact source in Vespiary.

## Why

Native certificate CA creation and controller deployment currently require S3 references during configuration loading, although those operations use Kubernetes certificate APIs.
The repair gives only those resolved commands an ephemeral typed validation purpose through both loading and preflight.

## What changes

- Keep native profile, cluster identity, node identity, and certificate API validation intact.
- Keep all other commands strict and protect direct storage consumers before effects.
- Preserve direct CSI none and existing option error order.

## Scope

One coherent external source unit starts at the handoff-linked `4e0fdbaf21db818706fdf67b3e56201d34dfd433`.
The source unit contains the signature migration, exact allowlist, direct-entry guards, and behavioral regression tests.
Dependencies, manifests, runtime profiles, API versions, storage behavior, CA semantics, and upstream maintenance stay outside this change.

## Blast radius

The change affects installer validation and trusted direct step callers.
Config, Env, serialized settings, records, and reports gain no command authority.
Zero and unknown purposes and all future or lookalike command paths remain strict.

## Verification

- Unchanged production reproduced the exact S3 refusal with zero requests for both certificate operations and the alias. Strict and valid-S3 native controls passed. The original byte-stable red is preserved in [baseline receipts](baseline-receipts.tar.gz).
- Focused config, cmd, steps, and recursive demos tests passed after one narrow fix round, with stable source and oracle bytes. Both attempts are preserved in [focused receipts](focused-receipts.tar.gz).
- Mandatory recovered `make verify` remains pending on the separately reviewed Docker budget and prerequisite plan. Focused tests do not replace it.
- No runtime qualification, installation, deployment, profile equivalence, or Goal 330 completion follows from source acceptance.

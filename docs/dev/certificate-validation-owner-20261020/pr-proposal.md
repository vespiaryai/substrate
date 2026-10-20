# Proposed source repair

Proposed title is `fix(ate-setup): scope native certificate S3 validation`.
This proposal describes the selected design. Production implementation and validation remain pending.
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

- Baseline-compatible real-root regression is prepared but has not compiled or run. Required red is the exact existing S3 refusal with zero requests, plus a passing valid-S3 fixture control.
- Focused config, cmd, steps, and demos tests and mandatory recovered `make verify` remain pending under the bounded heavy slot and unchanged reviewed byte guard.
- No runtime qualification, installation, deployment, profile equivalence, or Goal 330 completion follows from source acceptance.

### Feature

**You own the design. Plan, review, verify.** Delegate implementation. Stay in the lead.

1. `how` over the affected subsystem.
2. `architect` for parallel design exploration.
3. Write the throughput checkpoint as four todo items. A dimension that genuinely does not apply (single file, no fan-out) keeps its item with `n/a: <reason>` rather than being dropped:
   - **Blocking first steps.** Gates run before fan-out.
   - **Independent workstreams.** Disjoint files, services, or layers parallelize. Shared writes serialize.
   - **Shared mutable state.** Default to splitting the target (the **separate-before-serializing-shared-state** principle skill). Serialize only for real invariants.
   - **Smallest safe decomposition.** If one worker is best, name why.
4. Delegate code-writing to a subagent using your configured feature model (default `grok-4.7-xhigh-fast`) with a specific scope (file paths, named data shape and its organizing structure per **principle-model-the-domain**, a state machine over scattered booleans, a table/registry over branching, a typed model over repeated shape assumptions, chosen before the delegate writes logic, and success criteria). When the implementation admits multiple valid shapes (error handling, abstraction layer, test structure), delegate via the **arena** skill instead so the runners surface the alternatives and the cross-judge guards the pick. Mandatory: no skip-with-reason escape, and Laziness Protocol does not override it (the gain is review separation, not lines saved). A subagent forbidden to spawn satisfies this by owning the diff directly with the same review separation. No "standing by" reply that waits on a nested agent. Comments per **Comments**. Surgical edits, re-ground against the source for upstream-derived files. Port shared-primitive improvements to all consumers and verify each. Commit liberally.
5. Verify on the matching surface. "Inconclusive" or wrong-surface is not a pass. Flag it.
6. Rebase into small, ordered commits. Stack follow-ups.
   Use the **sequence-verifiable-units** principle skill, building, verifying, and committing each small unit before the next.
7. If the design is contested, `interrogate` before shipping.
8. Run **Opening a PR**.

Code-coupled work (one feature, one migration) goes to a single owner with the checkpoint inline. That owner fans out internally after the blocking phase. Parent-level fan-out is for slices that produce independent artifacts (audits, cross-subsystem investigations, competing experiments). Rewrite the checkpoint at phase boundaries. Spawn a fresh owner rather than chaining interrupts.

**Reply:** what you built, what you chose and why, the throughput checkpoint, open decisions. Tables for design alternatives.

## Dispatch status

1. Done by direct source tracing. Nested workers and model calls are forbidden.
2. Skip: the task mandates minimal reuse of the qualified driver. No nested design workers or new framework.
3. Blocking first steps. Read preferences, exact source and reviews, retained mock receipts, denial and root closure.
   Independent workstreams. n/a because this one-owner source-only command adaptation forbids nested work.
   Shared mutable state. The new external bundle has one writer. Old bundles, receipts, native manifests and the repository stay frozen.
   Smallest safe decomposition. One copied driver retains native owner/unit/release responsibilities. Root owns grants and closure.
4. Done directly under Feature's no-nested-worker exception. Data shape is the existing owner/unit/release receipt set plus a literal expected case list and source-byte inventory.
5. Pending. No prepared driver, helper, fixture, import, syntax check, test, or native command has executed.
6. Skip: this dispatch forbids commits, PRs, rebases, and integration.
7. Skip: no shipping or contested architecture. Root owns independent review.
8. Skip: root owns publication and integration. Split PR rules were read, with no main substitution.

The how and architect routes were read. Delegated exploration is unavailable under the explicit no-nested-worker instruction.
Model the Domain keeps complete case IDs in one JSON list. Laziness Protocol keeps the qualified native owner unchanged apart from input and evidence adaptation.
Prove It Works adds actual source-byte copies and actual case-ID receipts to the future run. Sequence Work into Verifiable Units separates preparation, offline execution, root closure and real bootstrap.
The exact old driver and proposal remain frozen. No runtime acceptance follows from source-text generation.

## Current dispatch

Task task_3ff8df1d0a41, dispatch ctx_913464a561fe. The copied status above describes its original dispatch only.
Throughput checkpoint. Blocking first steps are reviewer release, current source hashes, and pending/root record reconciliation.
Independent workstreams are n/a because nested workers are forbidden and one existing owner is required.
Shared mutable state has one writer in this new bundle. Application and historical evidence remain frozen.
Smallest safe decomposition keeps source preparation, one later offline grant, execution, and root acceptance separate.
Model the Domain retains the explicit JSON case list and existing receipt set.
Laziness Protocol retains owner/unit/release unchanged except source inventory, IDs, first-use paths, and mandated guard-before-suite ordering.
Prove It Works limits preparation to read source and actual hash checks. Imports, syntax, tests, native units, and flock are UNRUN.
Sequence Work into Verifiable Units defers PR/integration and native qualification. Root owns independent review and the later grant.
The installed official skill-creator replaces unavailable Cursor create-skill. Delegated How/architect and cross-model trail review did not run under the explicit no-nested-worker override.

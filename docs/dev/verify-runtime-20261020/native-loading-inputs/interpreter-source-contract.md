# Interpreter source support checkpoint

Installed support remains refused. `INTERPRETER_SUPPORT` is None. The private
synthetic fixture contract has exactly schema, scope, executable and sha256.
Its schema is `interpreter-source-contract-1` and scope is `owned-fixture-only`.
The parent captures and verifies its pinned bytes before launch. It is no installed
acquisition grant and supplies no fallback inventory.

The coordinator retained official CPython 3.14.8 source commit
8e6e75d9102e39bed2a2b279203a396741180f12. In Python/import.c, lines 2853-2930
enumerate bootstrap, enabled standard/test and custom names. Custom names already
present are not duplicated. Lookup at 2977-3031 prefers bootstrap, then custom,
then enabled standard/test tables. A custom null payload can exclude a name.
find_frozen checks payload and size. is_frozen at 4670 returns exactly the
FROZEN_OKAY predicate. Enumeration at 4688 calls that enumerator, and imp_methods
registers both methods at 4924-4925. The generated clinic header exposes their
method definitions. Suffix enumeration at 4453 follows the dynamic suffix table
in order and allows an empty list when dynamic loading is absent. This supports
the proposed ordered predicate inventory for those source bytes. It does not
prove that every reported frozen payload can execute.

Fedora packaging commit c556ba1e0561cda313c374351bebed83a252bc8b pins release
3.14.8-1 and the official Python-3.14.8.tar.xz SHA512
f9e6809b0c45d90fcc174b8051e15058a3037981c9136c598d110a118a22cbbb8263fbd677e07b2b9d93e1aa83cd9cb835b61b6af898fd301d1080a29c2156fe.
The coordinator's archive receipt reports that match and exact equality of the
two import source files with the upstream Git bytes. Public Koji getBuild
3111958 binds the packaging commit. Its getRPM records and installed header
receipt join both python3 and python3-libs NVRs and legacy SIGMD5 IDs.
Header metadata does not establish installed-file integrity.

The spec declares five patches. Their targets concern site/sysconfig install
schemes, expat, POP3 controls, stdlib module version checks and JIT build flags.
None directly targets Python/import.c or its generated method header. The spec
also regenerates configure and generated sources, enables shared libraries and
builds optimized/debug/freethreading configurations. Text inspection of those
sections is not a full independent build-equivalence review. No patch was applied,
build performed or installed executable verified in this phase.

Before installed support can be added, independently review the complete spec,
patch application and generated-source relationship, exact binary/source and
installed-file joins, and startup dependencies including json's attempted _json
acceleration. Root must review that evidence and grant the exact launch scope.
Missing APIs or evidence refuse. There is no sys.modules or static-list fallback.
Owned fixture success can prove only this synthetic adapter and its lifecycle.

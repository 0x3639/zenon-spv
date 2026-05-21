Fix list for 
zenon-spv
Must fix before production
Fix VerifySegment linkage after rejected blocks
Do not set prev = b after a rejected block.
Track linkage using the recomputed previous hash, not the claimed BlockHash.
Implement producer-set / quorum verification
Verify each header signer is an authorized producer for that height.
Until this exists, ACCEPT must be caveated as “locally consistent under checkpoint assumptions,” not “valid Zenon chain.”
Downgrade CLI/user-facing ACCEPT language
Print a warning that producer-set verification is not implemented.
Make weak-subjectivity/checkpoint assumptions explicit.
Add full resource bounds
Bound flat commitment evidence size.
Bound account segment size.
Bound total bundle bytes.
Enforce MaxHeaderBytes or remove it.
Return REFUSED when bounds are exceeded.
Make state-save failures fatal after threshold
syncer.Loop should not silently continue forever if SaveHeaderState fails.
Add consecutive failure counter and exit/alert after N failures.
Serious correctness / reliability fixes
Replace findHeaderAtHeight linear scan
Use map[height]Header or direct contiguous-window index.
Avoid O(blocks × window) behavior during segment verification.
Deduplicate content-hash calculation
Move duplicated flatContentHash / contentHashOfDecoded logic into one shared internal function.
Add source-parity tests against real Momentum content.
Add empty-content Momentum tests
Test sha3sum(nil) / empty content behavior.
Ensure empty evidence never passes membership.
Clarify DataHash derivation
Ensure DataHash is locally derived from raw Momentum Data, never trusted from RPC.
Add test proving tampered DataHash is rejected.
Clarify embedded contract block acceptance
Document that embedded blocks rely entirely on commitment/header validity.
Add tests for empty pubkey/signature rules.
Documentation fixes
Update stale README
It currently understates implemented scope.
Mention commitment proofs, fetcher, segment verifier, syncer, and CLI tools.
Document weak-subjectivity assumptions
Checkpoints are not full consensus validation.
Multi-peer agreement is not quorum proof.
Rename or clarify “SPV” claims
Current repo is closer to a bounded attestation verifier.
Avoid implying full Zenon light-client security until producer-set/quorum exists.
Test suite additions
Add test: rejected block does not become linkage parent.
Add test: block after rejected block cannot pass via forged previous hash.
Add test: producer-set verification missing emits warning / caveat.
Add test: oversized flat commitment evidence returns REFUSED.
Add test: oversized segment returns REFUSED.
Add test: MaxHeaderBytes enforced.
Add test: state-save failure loop exits after threshold.
Add test: window shrink keeps newest headers and documents behavior.
Add test: duplicate content-hash implementations produce identical output.
Minor cleanup
Replace hand-rolled uitos with strconv.FormatUint.
Replace in-place good := results[:0] filter with a fresh slice for clarity.
Fix misleading sortUint64 comment.
Clarify Worst() semantics or rename it.
Normalize type usage between Policy.W uint64 and MaxHeaders int.
One-line priority:
Fix segment linkage bug first, then producer-set verification, then resource bounds, then user-facing caveats.
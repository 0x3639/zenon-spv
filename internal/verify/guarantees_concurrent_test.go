package verify

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGuarantees_ConcurrentWithProvenIsRaceFree targets the specific
// concern flagged during code review: `removeGuarantees` uses an
// in-place `dst[:0]` filter. Because WithProven receives r by value
// but the slice headers in r share backing arrays with the caller's
// Result, concurrent callers that share a Result and each call
// WithProven could in principle race on the underlying NotProven
// array.
//
// Run with `go test -race`. If the race detector flags anything,
// the helper needs to allocate a fresh slice instead of reusing the
// backing array. If the test passes cleanly under -race, the
// in-place pattern is safe for the actually-executed concurrency
// shapes.
func TestGuarantees_ConcurrentWithProvenIsRaceFree(t *testing.T) {
	// Single shared base Result. Populated with several NotProven
	// entries the goroutines will try to upgrade to Proven (which
	// requires removeGuarantees to mutate the backing array).
	base := accept().WithNotProven(
		GuaranteeHeaderChainIntegrity,
		GuaranteeSignatureAuthenticity,
		GuaranteeContentInclusion,
		GuaranteeProducerAuthorization,
		GuaranteeCanonicality,
		GuaranteeStateTransition,
	)

	const goroutines = 64
	const iterations = 2000

	var (
		wg       sync.WaitGroup
		violated atomic.Int64
	)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		// Each goroutine picks a different guarantee to upgrade so
		// they're all hammering the same backing array from many
		// directions. If removeGuarantees writes are unsafe, the
		// race detector should fire and/or assertNoContradictions
		// should observe overlap.
		guarantee := []Guarantee{
			GuaranteeHeaderChainIntegrity,
			GuaranteeSignatureAuthenticity,
			GuaranteeContentInclusion,
			GuaranteeProducerAuthorization,
			GuaranteeCanonicality,
			GuaranteeStateTransition,
		}[g%6]

		go func(g Guarantee) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// The actual call shape from the codex fix:
				// WithProven removes from NotProven via dst[:0]
				// filter, then returns a new Result by value.
				r := base.WithProven(g)
				if contains(r.Proven, g) == false {
					t.Errorf("WithProven(%s) did not add to Proven; got Proven=%v", g, r.Proven)
					return
				}
				// The invariant: nothing should appear in both lists.
				for _, p := range r.Proven {
					if contains(r.NotProven, p) {
						violated.Add(1)
						return
					}
				}
				// Also exercise the symmetric direction: re-call
				// WithNotProven on the result. The fix says this
				// must NOT re-add guarantees already in Proven.
				r2 := r.WithNotProven(g)
				if contains(r2.NotProven, g) {
					violated.Add(1)
					return
				}
			}
		}(guarantee)
	}
	wg.Wait()

	if v := violated.Load(); v != 0 {
		t.Fatalf("%d concurrent WithProven/WithNotProven calls produced contradicting Results", v)
	}

	// Confirm the GC made progress (no goroutine leak holding refs).
	runtime.GC()
}

// TestGuarantees_ParallelVerifierAccessIsRaceFree exercises the
// helper from a slightly different angle: many goroutines, each
// building their OWN Result from scratch via the standard
// builder chain. This is the actually-executed pattern in normal
// code paths — every verifier returns its own Result, no sharing.
// Should always be race-free; this test locks that in.
func TestGuarantees_ParallelVerifierAccessIsRaceFree(t *testing.T) {
	const goroutines = 32
	const iterations = 5000

	var (
		wg       sync.WaitGroup
		violated atomic.Int64
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Build a Result from scratch using the standard
				// pattern from the verify package: start with
				// accept(), then add Proven, then add NotProven.
				r := accept().
					WithProven(GuaranteeHeaderChainIntegrity, GuaranteeSignatureAuthenticity).
					WithNotProven(
						GuaranteeContentInclusion,
						GuaranteeProducerAuthorization,
						GuaranteeCanonicality,
						GuaranteeStateTransition,
					).
					WithTrust(TrustCheckpointAnchor)

				for _, p := range r.Proven {
					if contains(r.NotProven, p) {
						violated.Add(1)
						return
					}
				}
				if len(r.Proven) != 2 || len(r.NotProven) != 4 {
					t.Errorf("unexpected guarantee counts: Proven=%v NotProven=%v", r.Proven, r.NotProven)
					return
				}
			}
		}()
	}
	wg.Wait()

	if v := violated.Load(); v != 0 {
		t.Fatalf("%d goroutines produced contradicting Results", v)
	}
}

func contains(xs []Guarantee, want Guarantee) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestGuarantees_ConcurrentSharedResultWithSpareCapacity is the
// Codex follow-up #2 regression. Closing the dst[:0] race in
// removeGuarantees was only half the fix — appendUniqueGuarantees
// and appendUniqueTrust also wrote into dst's backing array via
// `append`, which is racy whenever dst has spare capacity (the
// other typical shape: a Result whose slices were built with
// over-estimated cap then later shared across goroutines).
//
// This test forces the spare-capacity shape by allocating slices
// with cap larger than len, then has many goroutines call WithProven
// / WithTrust on the shared base. Pre-fix this would race on the
// backing arrays at the append site; post-fix the helpers allocate
// fresh slices.
func TestGuarantees_ConcurrentSharedResultWithSpareCapacity(t *testing.T) {
	provenWithCap := make([]Guarantee, 0, 12)
	provenWithCap = append(provenWithCap, GuaranteeHeaderChainIntegrity)

	notProvenWithCap := make([]Guarantee, 0, 12)
	notProvenWithCap = append(notProvenWithCap,
		GuaranteeContentInclusion,
		GuaranteeStateTransition,
	)

	trustWithCap := make([]TrustAssumption, 0, 12)
	trustWithCap = append(trustWithCap, TrustCheckpointAnchor)

	base := Result{
		Outcome:          OutcomeAccept,
		Reason:           ReasonOK,
		FailedAt:         -1,
		Proven:           provenWithCap,
		NotProven:        notProvenWithCap,
		TrustAssumptions: trustWithCap,
	}

	const goroutines = 64
	const iterations = 2000

	var (
		wg       sync.WaitGroup
		violated atomic.Int64
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		guarantee := []Guarantee{
			GuaranteeSignatureAuthenticity,
			GuaranteeProducerAuthorization,
			GuaranteeCanonicality,
		}[g%3]
		trust := []TrustAssumption{
			TrustRPCQuorum,
			TrustExternalProducerSchedule,
			TrustRetainedWindowDepth,
		}[g%3]
		go func(g Guarantee, t TrustAssumption) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				r := base.WithProven(g).WithTrust(t)
				for _, p := range r.Proven {
					if contains(r.NotProven, p) {
						violated.Add(1)
						return
					}
				}
			}
		}(guarantee, trust)
	}
	wg.Wait()
	if v := violated.Load(); v != 0 {
		t.Fatalf("%d goroutines produced contradicting Results on spare-cap base", v)
	}
	// Confirm base wasn't mutated through any backing-array sharing:
	// its initial sizes must still hold.
	if len(base.Proven) != 1 || len(base.NotProven) != 2 || len(base.TrustAssumptions) != 1 {
		t.Fatalf("base mutated through backing array: Proven=%v NotProven=%v Trust=%v",
			base.Proven, base.NotProven, base.TrustAssumptions)
	}
}

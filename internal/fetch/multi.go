package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ErrPeerDisagreement signals that two or more peers returned
// internally consistent but mutually inconsistent answers for the same
// query — the spec's REFUSED-on-disagreement signal
// (zenon-spv-vault/spec/spv-implementation-guide.md §9.1).
var ErrPeerDisagreement = errors.New("peers disagree (suspected isolation, fork, or operator compromise)")

// ErrNotEnoughPeers signals that fewer than the configured quorum K
// of peers returned a usable answer.
var ErrNotEnoughPeers = errors.New("not enough peers reached quorum")

// MultiClient fans queries out to N peers, recomputes each peer's
// claim locally, and returns the answer only if at least K of the
// peers agree byte-for-byte on the recomputed result. Disagreement
// (ANY peer that responded with a *different* internally-consistent
// answer) returns ErrPeerDisagreement, never a silent pick.
//
// Network errors and individual peer hash-mismatches are tolerated
// up to N-K of them; below that, ErrNotEnoughPeers.
//
// The fan-out is concurrent; ctx cancels in-flight requests when one
// peer's response is enough to decide an early failure.
type MultiClient struct {
	Peers  []*Client
	Quorum int // K; must be 1..len(Peers). Default len(Peers).
}

// NewMultiClient builds a MultiClient with the given URLs. The default
// quorum is len(urls) — i.e., unanimous agreement. Lower the quorum
// only with eyes open: it weakens the security argument.
func NewMultiClient(urls []string) *MultiClient {
	peers := make([]*Client, len(urls))
	for i, u := range urls {
		peers[i] = NewClient(u)
	}
	return &MultiClient{Peers: peers, Quorum: len(urls)}
}

// peerResult captures one peer's response to a fan-out query.
type peerResult struct {
	url     string
	headers []chain.Header
	err     error
}

// peerDetailedResult captures one peer's detailed response.
type peerDetailedResult struct {
	url      string
	detailed []DetailedHeader
	err      error
}

// FetchByHeightDetailed fans FetchByHeightDetailed to all peers and
// returns the slice only if at least Quorum peers agree on every
// header hash at every height. Cross-peer agreement on the (signed)
// momentum hash transitively implies agreement on the parsed
// content, since the content hash is bound into the signed envelope.
func (m *MultiClient) FetchByHeightDetailed(ctx context.Context, start, count uint64) ([]DetailedHeader, error) {
	if len(m.Peers) == 0 {
		return nil, errors.New("multi: no peers configured")
	}
	q := m.Quorum
	if q < 1 {
		q = len(m.Peers)
	}
	if q > len(m.Peers) {
		return nil, fmt.Errorf("multi: quorum %d > peers %d", q, len(m.Peers))
	}

	results := make([]peerDetailedResult, len(m.Peers))
	var wg sync.WaitGroup
	for i, p := range m.Peers {
		wg.Add(1)
		go func(i int, p *Client) {
			defer wg.Done()
			d, err := p.FetchByHeightDetailed(ctx, start, count)
			results[i] = peerDetailedResult{url: p.URL, detailed: d, err: err}
		}(i, p)
	}
	wg.Wait()

	return reconcileDetailed(results, q)
}

// FetchByHeight fans the request to all peers and returns the slice
// only if at least Quorum peers returned identical (recomputed)
// header hashes for every height. If peers disagree, returns
// ErrPeerDisagreement with a per-peer summary embedded in the error.
func (m *MultiClient) FetchByHeight(ctx context.Context, start, count uint64) ([]chain.Header, error) {
	if len(m.Peers) == 0 {
		return nil, errors.New("multi: no peers configured")
	}
	q := m.Quorum
	if q < 1 {
		q = len(m.Peers)
	}
	if q > len(m.Peers) {
		return nil, fmt.Errorf("multi: quorum %d > peers %d", q, len(m.Peers))
	}

	results := make([]peerResult, len(m.Peers))
	var wg sync.WaitGroup
	for i, p := range m.Peers {
		wg.Add(1)
		go func(i int, p *Client) {
			defer wg.Done()
			h, err := p.FetchByHeight(ctx, start, count)
			results[i] = peerResult{url: p.URL, headers: h, err: err}
		}(i, p)
	}
	wg.Wait()

	return reconcileByHeight(results, q)
}

// FetchFrontierAtAgreedHeight asks each peer for its frontier and
// picks the conservative agreed target = median(frontier_heights) -
// safetyMargin. Median (rather than min) prevents a single Byzantine
// peer reporting an ancient frontier from dragging the target
// arbitrarily backward — the F1 attack ("frontier drag") that caused
// the watch loop to silently report "caught up" forever (D1).
//
// After picking the target, it runs FetchByHeight(target, 1) which
// requires Quorum peers to agree on the (height, hash) at that height.
// Disagreement → ErrPeerDisagreement.
func (m *MultiClient) FetchFrontierAtAgreedHeight(ctx context.Context, safetyMargin uint64) (chain.Header, error) {
	if len(m.Peers) == 0 {
		return chain.Header{}, errors.New("multi: no peers configured")
	}
	heights := make([]uint64, len(m.Peers))
	errs := make([]error, len(m.Peers))
	var wg sync.WaitGroup
	for i, p := range m.Peers {
		wg.Add(1)
		go func(i int, p *Client) {
			defer wg.Done()
			h, err := p.FetchFrontier(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			heights[i] = h.Height
		}(i, p)
	}
	wg.Wait()

	usable := make([]uint64, 0, len(m.Peers))
	for i, h := range heights {
		if errs[i] != nil {
			continue
		}
		usable = append(usable, h)
	}
	if len(usable) < m.Quorum {
		return chain.Header{}, fmt.Errorf("%w: %d/%d peers reached on frontier", ErrNotEnoughPeers, len(usable), len(m.Peers))
	}
	// Median tolerates up to floor((n-1)/2) Byzantine peers without
	// dragging the target. Sort in place (caller owns `usable`).
	sortUint64(usable)
	medianHeight := usable[len(usable)/2]

	if medianHeight <= safetyMargin {
		return chain.Header{}, fmt.Errorf("median frontier height %d <= safetyMargin %d", medianHeight, safetyMargin)
	}
	target := medianHeight - safetyMargin

	headers, err := m.FetchByHeight(ctx, target, 1)
	if err != nil {
		return chain.Header{}, err
	}
	return headers[0], nil
}

// sortUint64 is a tiny in-place insertion sort; the slices we sort
// are bounded by len(Peers), typically ≤ 5, so insertion sort beats
// the runtime cost of importing sort.
func sortUint64(s []uint64) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// reconcileDetailed collects per-peer DetailedHeader slices, requires
// at least q peers returned a usable slice, and requires every
// (Height, HeaderHash, PublicKey, Signature) tuple to be identical
// across those peers. The PublicKey/Signature inclusion (F3) prevents
// a peer from substituting an unhashed verifier-consumed field while
// agreeing on the hash. Returns the first usable peer's slice.
func reconcileDetailed(results []peerDetailedResult, q int) ([]DetailedHeader, error) {
	good := results[:0]
	var firstErrs []string
	for _, r := range results {
		if r.err != nil {
			firstErrs = append(firstErrs, fmt.Sprintf("  %s: %v", r.url, r.err))
			continue
		}
		good = append(good, r)
	}
	if len(good) < q {
		return nil, fmt.Errorf("%w: %d/%d peers usable; errors:\n%s",
			ErrNotEnoughPeers, len(good), q, strings.Join(firstErrs, "\n"))
	}
	pin := good[0]
	for _, r := range good[1:] {
		if len(r.detailed) != len(pin.detailed) {
			return nil, fmt.Errorf("%w: %s returned %d momentums, %s returned %d",
				ErrPeerDisagreement, r.url, len(r.detailed), pin.url, len(pin.detailed))
		}
		for i := range pin.detailed {
			if r.detailed[i].Header.Height != pin.detailed[i].Header.Height {
				return nil, fmt.Errorf("%w: %s height[%d]=%d vs %s height[%d]=%d",
					ErrPeerDisagreement, r.url, i, r.detailed[i].Header.Height,
					pin.url, i, pin.detailed[i].Header.Height)
			}
			if r.detailed[i].Header.HeaderHash != pin.detailed[i].Header.HeaderHash {
				return nil, fmt.Errorf("%w: at height %d, %s hash=%x vs %s hash=%x",
					ErrPeerDisagreement, pin.detailed[i].Header.Height,
					r.url, r.detailed[i].Header.HeaderHash,
					pin.url, pin.detailed[i].Header.HeaderHash)
			}
			if !bytes.Equal(r.detailed[i].Header.PublicKey, pin.detailed[i].Header.PublicKey) {
				return nil, fmt.Errorf("%w: at height %d, %s and %s disagree on public_key",
					ErrPeerDisagreement, pin.detailed[i].Header.Height, r.url, pin.url)
			}
			if !bytes.Equal(r.detailed[i].Header.Signature, pin.detailed[i].Header.Signature) {
				return nil, fmt.Errorf("%w: at height %d, %s and %s disagree on signature",
					ErrPeerDisagreement, pin.detailed[i].Header.Height, r.url, pin.url)
			}
		}
	}
	return pin.detailed, nil
}

// FetchAccountBlocksByHeight fans the request to all peers and
// returns the slice only if at least Quorum peers agree on every
// block hash. Disagreement → ErrPeerDisagreement.
func (m *MultiClient) FetchAccountBlocksByHeight(ctx context.Context, addressBech32 string, start, count uint64) ([]chain.AccountBlock, error) {
	if len(m.Peers) == 0 {
		return nil, errors.New("multi: no peers configured")
	}
	q := m.Quorum
	if q < 1 {
		q = len(m.Peers)
	}
	if q > len(m.Peers) {
		return nil, fmt.Errorf("multi: quorum %d > peers %d", q, len(m.Peers))
	}

	type peerBlocksResult struct {
		url    string
		blocks []chain.AccountBlock
		err    error
	}
	results := make([]peerBlocksResult, len(m.Peers))
	var wg sync.WaitGroup
	for i, p := range m.Peers {
		wg.Add(1)
		go func(i int, p *Client) {
			defer wg.Done()
			b, err := p.FetchAccountBlocksByHeight(ctx, addressBech32, start, count)
			results[i] = peerBlocksResult{url: p.URL, blocks: b, err: err}
		}(i, p)
	}
	wg.Wait()

	good := results[:0]
	var firstErrs []string
	for _, r := range results {
		if r.err != nil {
			firstErrs = append(firstErrs, fmt.Sprintf("  %s: %v", r.url, r.err))
			continue
		}
		good = append(good, r)
	}
	if len(good) < q {
		return nil, fmt.Errorf("%w: %d/%d peers usable; errors:\n%s",
			ErrNotEnoughPeers, len(good), q, strings.Join(firstErrs, "\n"))
	}
	pin := good[0]
	for _, r := range good[1:] {
		if len(r.blocks) != len(pin.blocks) {
			return nil, fmt.Errorf("%w: %s returned %d blocks, %s returned %d",
				ErrPeerDisagreement, r.url, len(r.blocks), pin.url, len(pin.blocks))
		}
		for i := range pin.blocks {
			if r.blocks[i].BlockHash != pin.blocks[i].BlockHash {
				return nil, fmt.Errorf("%w: at height %d, %s hash=%x vs %s hash=%x",
					ErrPeerDisagreement, pin.blocks[i].Height,
					r.url, r.blocks[i].BlockHash,
					pin.url, pin.blocks[i].BlockHash)
			}
			// F3: account blocks carry pk/sig that ride along the
			// hash; substitution by a malicious peer is caught here.
			if !bytes.Equal(r.blocks[i].PublicKey, pin.blocks[i].PublicKey) {
				return nil, fmt.Errorf("%w: at block height %d, %s and %s disagree on public_key",
					ErrPeerDisagreement, pin.blocks[i].Height, r.url, pin.url)
			}
			if !bytes.Equal(r.blocks[i].Signature, pin.blocks[i].Signature) {
				return nil, fmt.Errorf("%w: at block height %d, %s and %s disagree on signature",
					ErrPeerDisagreement, pin.blocks[i].Height, r.url, pin.url)
			}
		}
	}
	return pin.blocks, nil
}

// reconcileByHeight collects per-peer slices, requires at least q
// peers returned a usable slice, and requires every (Height,
// HeaderHash, PublicKey, Signature) tuple to be identical across
// those peers. PublicKey/Signature inclusion (F3) prevents a peer
// from substituting an unhashed verifier-consumed field while still
// agreeing on the hash. Any disagreement is fatal.
func reconcileByHeight(results []peerResult, q int) ([]chain.Header, error) {
	good := results[:0]
	var firstErrs []string
	for _, r := range results {
		if r.err != nil {
			firstErrs = append(firstErrs, fmt.Sprintf("  %s: %v", r.url, r.err))
			continue
		}
		good = append(good, r)
	}
	if len(good) < q {
		return nil, fmt.Errorf("%w: %d/%d peers usable; errors:\n%s",
			ErrNotEnoughPeers, len(good), q, strings.Join(firstErrs, "\n"))
	}
	// Pin against the first usable peer's slice; require all others
	// agree on (Height, HeaderHash, PublicKey, Signature) at every index.
	pin := good[0]
	for _, r := range good[1:] {
		if len(r.headers) != len(pin.headers) {
			return nil, fmt.Errorf("%w: %s returned %d headers, %s returned %d",
				ErrPeerDisagreement, r.url, len(r.headers), pin.url, len(pin.headers))
		}
		for i := range pin.headers {
			if r.headers[i].Height != pin.headers[i].Height {
				return nil, fmt.Errorf("%w: %s height[%d]=%d vs %s height[%d]=%d",
					ErrPeerDisagreement, r.url, i, r.headers[i].Height,
					pin.url, i, pin.headers[i].Height)
			}
			if r.headers[i].HeaderHash != pin.headers[i].HeaderHash {
				return nil, fmt.Errorf("%w: at height %d, %s hash=%x vs %s hash=%x",
					ErrPeerDisagreement, pin.headers[i].Height,
					r.url, r.headers[i].HeaderHash,
					pin.url, pin.headers[i].HeaderHash)
			}
			if !bytes.Equal(r.headers[i].PublicKey, pin.headers[i].PublicKey) {
				return nil, fmt.Errorf("%w: at height %d, %s and %s disagree on public_key",
					ErrPeerDisagreement, pin.headers[i].Height, r.url, pin.url)
			}
			if !bytes.Equal(r.headers[i].Signature, pin.headers[i].Signature) {
				return nil, fmt.Errorf("%w: at height %d, %s and %s disagree on signature",
					ErrPeerDisagreement, pin.headers[i].Height, r.url, pin.url)
			}
		}
	}
	return pin.headers, nil
}

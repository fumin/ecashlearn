package enforcer

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/fumin/ecashlearn/enforcer/types"
	"github.com/pkg/errors"
)

type PendingM6IDInfo struct {
	Vote           uint16
	ProposalHeight uint32
}

type Bundle struct {
	M6ID types.M6ID
	Vout int
	Info PendingM6IDInfo
}

// D2 is the withdrawal list described in BIP300.
type D2 struct {
	m map[SidechainNumber][]Bundle

	height int
	prevM4 M4

	withdrawalMaxAge             int
	withdrawalInclusionThreshold int
}

func newD2() *D2 {
	d2 := &D2{}
	d2.m = make(map[SidechainNumber][]Bundle)
	d2.m[2] = []Bundle{}
	d2.m[4] = []Bundle{}
	d2.m[9] = []Bundle{}
	d2.m[13] = []Bundle{}
	d2.m[24] = []Bundle{}
	d2.m[98] = []Bundle{}
	d2.m[99] = []Bundle{}
	d2.m[255] = []Bundle{}

	d2.prevM4 = M4{Enum: M4VersionOneByte} // no-op

	d2.withdrawalMaxAge = 10
	d2.withdrawalInclusionThreshold = 5
	return d2
}

func (d2 *D2) HandleMsgs(ms []Message, height int) error {
	d2.height = height

	if err := d2.checkVotedM6Withdrawn(ms); err != nil {
		return errors.Wrap(err, "")
	}

	for _, m := range ms {
		if err := d2.handle(m); err != nil {
			if _, ok := errors.Cause(err).(InvalidateBlockError); ok {
				return errors.Wrap(err, "")
			}
		}
	}

	d2.delExpired()
	return nil
}

func (d2 *D2) Snapshot() map[SidechainNumber][]Bundle {
	m := make(map[SidechainNumber][]Bundle, len(d2.m))
	for s, bs := range d2.m {
		bs2 := make([]Bundle, 0, len(bs))
		for _, b := range bs {
			b2 := Bundle{M6ID: make([]byte, len(b.M6ID)), Info: b.Info}
			copy(b2.M6ID, b.M6ID)
			bs2 = append(bs2, b2)
		}
		m[s] = bs2
	}
	return m
}

func (d2 *D2) handle(msg Message) error {
	var err error
	switch m := msg.Msg.(type) {
	case M3:
		err = d2.handleM3(msg.Output, m)
	case M4:
		err = d2.handleM4(m)
	case M6:
		err = d2.handleM6(m)
	}
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("height %d tx %d", msg.Height, msg.Transaction))
	}
	return nil
}

func cmpBundleChrono(a, b Bundle) int {
	aH, bH := a.Info.ProposalHeight, b.Info.ProposalHeight
	if aH != bH {
		return cmp.Compare(aH, bH)
	}
	return cmp.Compare(a.Vout, b.Vout)
}

func (d2 *D2) handleM3(vout int, m M3) error {
	bundles := d2.m[m.SidechainN]
	b := Bundle{M6ID: m.Bundle, Vout: vout, Info: PendingM6IDInfo{Vote: 1, ProposalHeight: uint32(d2.height)}}
	prevI := slices.IndexFunc(bundles, func(bi Bundle) bool { return slices.Equal(bi.M6ID, b.M6ID) })
	if prevI != -1 {
		// If any of the following conditions hold, the block is considered invalid and MUST be rejected:
		// The 32-byte M6ID has already been proposed in an M3 message in a previous block, that has not been paid out.
		// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#semantics-2
		return InvalidateBlockError{e: fmt.Sprintf("duplicate bundle %#v", bundles[prevI])}
	}

	bundles = append(bundles, b)
	slices.SortFunc(bundles, cmpBundleChrono)
	d2.m[m.SidechainN] = bundles
	return nil
}

func upvote(want int, bundles []Bundle) ([]Bundle, error) {
	if !(want >= 0 && want < len(bundles)) {
		// M4 invalidates the block if it tries to upvote a bundle that doesn't exist.
		// For example, trying to upvote the 7th bundle on sidechain #2, when sidechain #2 has only three bundles.
		// https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0300.mediawiki#m4----ack-bundles
		return nil, InvalidateBlockError{e: fmt.Sprintf("%d out of bounds %d", want, len(bundles))}
	}
	for i := range bundles {
		if i == want {
			bundles[i].Info.Vote++
		} else {
			bundles[i].Info.Vote--
		}
	}
	return bundles, nil
}

func downvoteAll(bundles []Bundle) []Bundle {
	for i := range bundles {
		bundles[i].Info.Vote--
	}
	return bundles
}

type Votes struct {
	V       []int
	Alarm   int
	Abstain int
}

func (d2 *D2) handleM4Votes(votes Votes) error {
	sidechains := slices.Collect(maps.Keys(d2.m))
	slices.Sort(sidechains)
	for i, bi := range votes.V {
		if i >= len(sidechains) {
			// If the A.len() > ASN.len(), then this M4 MUST be considered invalid, and the whole block this M4 is included in MUST be considered invalid as well, because we are attempting to set withdrawal bundle votes for sidechain slots that are not active.
			// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#encoding-3
			return InvalidateBlockError{e: fmt.Sprintf("%d >= %d", i, len(sidechains))}
		}
		slot := sidechains[i]
		bundles := d2.m[slot]

		if bi == votes.Abstain {
			continue
		}
		if bi == votes.Alarm {
			d2.m[slot] = downvoteAll(bundles)
			continue
		}

		bundles, err := upvote(bi, bundles)
		if err != nil {
			return errors.Wrap(err, "")
		}
		d2.m[slot] = bundles
	}
	return nil
}

func (d2 *D2) handleM4Leading() error {
	for slot, bundles := range d2.m {
		leading, leadingVotes := 0, bundles[0].Info.Vote
		for i, b := range bundles {
			if b.Info.Vote > leadingVotes {
				leading, leadingVotes = i, b.Info.Vote
			}
		}
		by50 := true
		for _, b := range bundles {
			if !(leadingVotes > b.Info.Vote+50) {
				by50 = false
				break
			}
		}
		if !by50 {
			continue
		}

		var err error
		bundles, err = upvote(leading, bundles)
		if err != nil {
			return errors.Wrap(err, "")
		}

		d2.m[slot] = bundles
	}
	return nil
}

func intVotes[T uint8 | uint16](vs []T) []int {
	votes := make([]int, 0, len(vs))
	for _, v := range vs {
		votes = append(votes, int(v))
	}
	return votes
}

func (d2 *D2) handleM4(m M4) error {
	var err error
	switch m.Enum {
	case M4VersionRepeatPrevious:
		err = d2.handleM4(d2.prevM4)
	case M4VersionOneByte:
		votes := Votes{V: intVotes[uint8](m.OneByte), Alarm: 0xfe, Abstain: 0xff}
		err = d2.handleM4Votes(votes)
	case M4VersionTwoByte:
		votes := Votes{V: intVotes[uint16](m.TwoByte), Alarm: 0xfffe, Abstain: 0xffff}
		err = d2.handleM4Votes(votes)
	case M4VersionLeadingBy50:
		err = d2.handleM4Leading()
	default:
		err = errors.Errorf("unknown %d", m.Enum)
	}
	if err != nil {
		return errors.Wrap(err, "")
	}

	if m.Enum != M4VersionRepeatPrevious {
		d2.prevM4 = m
	}
	return nil
}

func (d2 *D2) canBeWithdrawn(b Bundle) error {
	if !(int(b.Info.Vote) > d2.withdrawalInclusionThreshold) {
		return errors.Errorf("!(%d > %d)", b.Info.Vote, d2.withdrawalInclusionThreshold)
	}

	age := d2.height - int(b.Info.ProposalHeight)
	if !(age <= d2.withdrawalMaxAge) {
		return errors.Errorf("!(%d <= %d)", age, d2.withdrawalMaxAge)
	}

	return nil
}

func (d2 *D2) handleM6(m M6) error {
	// A transaction ... MUST be considered invalid unless:
	// Its M6ID computed using the m6_to_id function, defined above, matches an M6ID in the BIP300 state that has reached enough votes to be included, meaning that its vote_count > WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD and age <= WITHDRAWAL_BUNDLE_MAX_AGE, where age = current_block_height - proposal_block_height.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#m6
	//
	// Moreover,
	// All non coinbase transactions in the block MUST be valid according to transaction validation rules defined above, if any one of them is invalid, then the whole block is invalid.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#block-validation-rules-specification
	bundles := d2.m[m.SidechainN]
	idx := slices.IndexFunc(bundles, func(b Bundle) bool {
		return slices.Equal(b.M6ID, m.M6)
	})
	if idx == -1 {
		return InvalidateBlockError{e: fmt.Sprintf("sidechain %d m6id %x not found", m.SidechainN, m.M6)}
	}
	b := bundles[idx]

	if err := d2.canBeWithdrawn(b); err != nil {
		return InvalidateBlockError{e: err.Error()}
	}

	bundles = slices.Delete(bundles, idx, idx+1)
	slices.SortFunc(bundles, cmpBundleChrono)
	d2.m[m.SidechainN] = bundles
	return nil
}

func (d2 *D2) checkVotedM6Withdrawn(ms []Message) error {
	m6s := make(map[string]Message)
	for _, m := range ms {
		if m6, ok := m.Msg.(M6); ok {
			m6s[hex.EncodeToString(m6.M6)] = m
		}
	}

	// The block in which an M6ID has the number of votes greater than WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD MUST include the corresponding M6, if the block does not include the corresponding M6 this block MUST be considered invalid.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#m4-ack-bundle
	for slot, bundles := range d2.m {
		for _, b := range bundles {
			if err := d2.canBeWithdrawn(b); err != nil {
				continue
			}
			if _, ok := m6s[hex.EncodeToString(b.M6ID)]; ok {
				continue
			}

			age := d2.height - int(b.Info.ProposalHeight)
			return InvalidateBlockError{e: fmt.Sprintf("height %d sidechain %d has bundle that can be withdrawn m6id %x votes %d age %d", d2.height, slot, b.M6ID, b.Info.Vote, age)}
		}
	}
	return nil
}

func (d2 *D2) delExpired() {
	for s, bundles := range d2.m {
		bundles = slices.DeleteFunc(bundles, func(b Bundle) bool {
			age := d2.height - int(b.Info.ProposalHeight)
			return age > d2.withdrawalMaxAge
		})
		slices.SortFunc(bundles, cmpBundleChrono)
		d2.m[s] = bundles
	}
}

func formatVotes(d2 *D2, votes Votes) string {
	sidechains := slices.Collect(maps.Keys(d2.m))
	slices.Sort(sidechains)

	svb := make([]string, 0)
	for i, bi := range votes.V {
		slot := sidechains[i]
		bundles := d2.m[slot]

		var biStr string
		switch bi {
		case votes.Abstain:
			biStr = ""
		case votes.Alarm:
			biStr = "!"
		default:
			biStr = strconv.Itoa(bi)
		}
		s := fmt.Sprintf("%d:%s/%d", slot, biStr, len(bundles))
		svb = append(svb, s)
	}

	return "[" + strings.Join(svb, " ") + "]"
}

func FormatMessage(d2 *D2, m Message) string {
	var s string
	switch msg := m.Msg.(type) {
	case M1:
		s = fmt.Sprintf("%d %d M1 %d", m.Height, m.Transaction, msg.SidechainN)
	case M3:
		s = fmt.Sprintf("%d %d M3 %d", m.Height, m.Transaction, msg.SidechainN)
	case M4:
		switch msg.Enum {
		case M4VersionRepeatPrevious:
			s = fmt.Sprintf("%d %d M4 RepeatPrevious", m.Height, m.Transaction)
		case M4VersionOneByte:
			votes := Votes{V: intVotes[uint8](msg.OneByte), Alarm: 0xfe, Abstain: 0xff}
			s = fmt.Sprintf("%d %d M4 %s", m.Height, m.Transaction, formatVotes(d2, votes))
		case M4VersionTwoByte:
			votes := Votes{V: intVotes[uint16](msg.TwoByte), Alarm: 0xfffe, Abstain: 0xffff}
			s = fmt.Sprintf("%d %d M4 %s", m.Height, m.Transaction, formatVotes(d2, votes))
		case M4VersionLeadingBy50:
			s = fmt.Sprintf("%d %d M4 LeadingBy50", m.Height, m.Transaction)
		default:
			s = fmt.Sprintf("%d %d M4 unknown", m.Height, m.Transaction)
		}
	case M5:
		slots := slices.Collect(maps.Keys(msg.Deposits))
		slices.Sort(slots)
		s = fmt.Sprintf("%d %d M5 %v", m.Height, m.Transaction, slots)
	case M6:
		s = fmt.Sprintf("%d %d M6 %d", m.Height, m.Transaction, msg.SidechainN)
	default:
		s = fmt.Sprintf("%d %d %T", m.Height, m.Transaction, msg)
	}
	return s
}

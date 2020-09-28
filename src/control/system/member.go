//
// (C) Copyright 2019-2020 Intel Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
// The Government's rights to use, modify, reproduce, release, perform, display,
// or disclose this software are subject to the terms of the Apache License as
// provided in Contract No. 8F-30005.
// Any reproduction of computer software, computer software documentation, or
// portions thereof marked with this legend must also reproduce the markings.
//

package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/common"
	"github.com/daos-stack/daos/src/control/lib/hostlist"
	"github.com/daos-stack/daos/src/control/logging"
)

// MemberState represents the activity state of DAOS system members.
type MemberState int

const (
	// MemberStateUnknown is the default invalid state.
	MemberStateUnknown MemberState = iota
	// MemberStateAwaitFormat indicates the member is waiting for format.
	MemberStateAwaitFormat
	// MemberStateStarting indicates the member has started but is not
	// ready.
	MemberStateStarting
	// MemberStateReady indicates the member has setup successfully.
	MemberStateReady
	// MemberStateJoined indicates the member has joined the system.
	MemberStateJoined
	// MemberStateStopping indicates prep-shutdown successfully run.
	MemberStateStopping
	// MemberStateStopped indicates process has been stopped.
	MemberStateStopped
	// MemberStateEvicted indicates rank has been evicted from DAOS system.
	MemberStateEvicted
	// MemberStateErrored indicates the process stopped with errors.
	MemberStateErrored
	// MemberStateUnresponsive indicates the process is not responding.
	MemberStateUnresponsive
)

func (ms MemberState) String() string {
	return [...]string{
		"Unknown",
		"AwaitFormat",
		"Starting",
		"Ready",
		"Joined",
		"Stopping",
		"Stopped",
		"Evicted",
		"Errored",
		"Unresponsive",
	}[ms]
}

// isTransitionIllegal indicates if given state transitions is legal.
//
// Map state combinations to true (illegal) or false (legal) and return negated
// value.
func (ms MemberState) isTransitionIllegal(to MemberState) bool {
	if ms == MemberStateUnknown {
		return true // no legal transitions
	}
	if ms == to {
		return true // identical state
	}
	return map[MemberState]map[MemberState]bool{
		MemberStateAwaitFormat: map[MemberState]bool{
			MemberStateEvicted: true,
		},
		MemberStateStarting: map[MemberState]bool{
			MemberStateEvicted: true,
		},
		MemberStateReady: map[MemberState]bool{
			MemberStateEvicted: true,
		},
		MemberStateJoined: map[MemberState]bool{
			MemberStateReady: true,
		},
		MemberStateStopping: map[MemberState]bool{
			MemberStateReady: true,
		},
		MemberStateEvicted: map[MemberState]bool{
			MemberStateReady:    true,
			MemberStateJoined:   true,
			MemberStateStopping: true,
		},
		MemberStateErrored: map[MemberState]bool{
			MemberStateReady:    true,
			MemberStateJoined:   true,
			MemberStateStopping: true,
		},
		MemberStateUnresponsive: map[MemberState]bool{
			MemberStateReady:    true,
			MemberStateJoined:   true,
			MemberStateStopping: true,
		},
	}[ms][to]
}

// Member refers to a data-plane instance that is a member of this DAOS
// system running on host with the control-plane listening at "Addr".
type Member struct {
	Rank           Rank
	UUID           uuid.UUID
	Addr           *net.TCPAddr
	FabricURI      string
	FabricContexts uint32
	state          MemberState
	Info           string
}

// MarshalJSON marshals system.Member to JSON.
func (sm *Member) MarshalJSON() ([]byte, error) {
	// use a type alias to leverage the default marshal for
	// most fields
	type toJSON Member
	return json.Marshal(&struct {
		Addr  string
		State int
		*toJSON
	}{
		Addr:   sm.Addr.String(),
		State:  int(sm.state),
		toJSON: (*toJSON)(sm),
	})
}

// UnmarshalJSON unmarshals system.Member from JSON.
func (sm *Member) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	// use a type alias to leverage the default unmarshal for
	// most fields
	type fromJSON Member
	from := &struct {
		Addr  string
		State int
		*fromJSON
	}{
		fromJSON: (*fromJSON)(sm),
	}

	if err := json.Unmarshal(data, from); err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", from.Addr)
	if err != nil {
		return err
	}
	sm.Addr = addr

	sm.state = MemberState(from.State)

	return nil
}

func (sm *Member) String() string {
	return fmt.Sprintf("%s/%d/%s", sm.Addr, sm.Rank, sm.State())
}

// State retrieves member state.
func (sm *Member) State() MemberState {
	return sm.state
}

// WithInfo adds info field and returns updated member.
func (sm *Member) WithInfo(msg string) *Member {
	sm.Info = msg
	return sm
}

// NewMember returns a reference to a new member struct.
func NewMember(rank Rank, uuidStr, uri string, addr *net.TCPAddr, state MemberState) *Member {
	// FIXME: Either require a valid uuid.UUID to be supplied
	// or else change the return signature to include an error
	newUUID := uuid.MustParse(uuidStr)
	return &Member{Rank: rank, UUID: newUUID, FabricURI: uri, Addr: addr, state: state}
}

// Members is a type alias for a slice of member references
type Members []*Member

// MemberResult refers to the result of an action on a Member.
type MemberResult struct {
	Addr    string
	Rank    Rank
	Action  string
	Errored bool
	Msg     string
	State   MemberState
}

// MarshalJSON marshals system.MemberResult to JSON.
func (mr *MemberResult) MarshalJSON() ([]byte, error) {
	// use a type alias to leverage the default marshal for
	// most fields
	type toJSON MemberResult
	return json.Marshal(&struct {
		State int
		*toJSON
	}{
		State:  int(mr.State),
		toJSON: (*toJSON)(mr),
	})
}

// UnmarshalJSON unmarshals system.MemberResult from JSON.
func (mr *MemberResult) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	// use a type alias to leverage the default unmarshal for
	// most fields
	type fromJSON MemberResult
	from := &struct {
		State int
		*fromJSON
	}{
		fromJSON: (*fromJSON)(mr),
	}

	if err := json.Unmarshal(data, from); err != nil {
		return err
	}

	mr.State = MemberState(from.State)

	return nil
}

// NewMemberResult returns a reference to a new member result struct.
//
// Host address and action fields are not always used so not populated here.
func NewMemberResult(rank Rank, err error, state MemberState) *MemberResult {
	result := MemberResult{Rank: rank, State: state}
	if err != nil {
		result.Errored = true
		result.Msg = err.Error()
	}

	return &result
}

// MemberResults is a type alias for a slice of member result references.
type MemberResults []*MemberResult

// HasErrors returns true if any of the member results errored.
func (smr MemberResults) HasErrors() bool {
	for _, res := range smr {
		if res.Errored {
			return true
		}
	}

	return false
}

type (
	onGroupMapChangedFn func(context.Context) error
	joinReqChan         chan *JoinRequest
	joinRespChan        chan *JoinResponse
)

// Membership tracks details of system members.
type Membership struct {
	sync.RWMutex
	log logging.Logger
	db  *Database

	sentGroupMapVer   uint32
	onGroupMapChanged []onGroupMapChangedFn
	joinReqs          joinReqChan
}

// OnGroupMapChanged registers callbacks to be run when the system
// group map changes.
func (m *Membership) OnGroupMapChanged(fns ...onGroupMapChangedFn) {
	m.onGroupMapChanged = append(m.onGroupMapChanged, fns...)
}

// runGroupMapUpdates compares the current GroupMap version to the
// last updated version and runs any registered callbacks if the
// new version is higher.
//
// NB: This must be run under a lock!
func (m *Membership) runGroupMapUpdates(ctx context.Context) error {
	dbMapVer, err := m.db.CurMapVersion()
	if err != nil {
		return err
	}

	if m.sentGroupMapVer >= dbMapVer {
		return &ErrGroupMapVerTooOld{dbMapVer, m.sentGroupMapVer}
	}

	m.log.Debug("invoking onGroupMapChanged callbacks")
	for _, fn := range m.onGroupMapChanged {
		if err := fn(ctx); err != nil {
			return err
		}
	}

	m.log.Debugf("system map version: %d", dbMapVer)
	m.sentGroupMapVer = dbMapVer
	return nil
}

// UpdateGroupMap signals the membership to run any callbacks registered
// to handle group map updates.
func (m *Membership) UpdateGroupMap(ctx context.Context) error {
	m.Lock()
	defer m.Unlock()

	return m.runGroupMapUpdates(ctx)
}

func (m *Membership) addMember(ctx context.Context, member *Member) error {
	_, err := m.db.FindMemberByUUID(member.UUID)
	if err == nil {
		return &ErrMemberExists{Rank: member.Rank}
	}
	m.log.Debugf("adding system member: %s", member)

	return m.db.AddMember(member)
}

func (m *Membership) updateMember(ctx context.Context, member *Member) error {
	old, err := m.db.FindMemberByUUID(member.UUID)
	m.log.Debugf("updating system member: %s->%s", old, member)
	if err != nil {
		return err
	}

	return m.db.UpdateMember(member)
}

// Add adds member to membership, returns member count.
func (m *Membership) Add(ctx context.Context, member *Member) (int, error) {
	m.Lock()
	defer m.Unlock()

	if err := m.addMember(ctx, member); err != nil {
		return -1, err
	}

	count, err := m.db.MemberCount()
	if err != nil {
		return -1, err
	}

	return count, nil
}

// Count returns the number of members.
func (m *Membership) Count() (int, error) {
	return m.db.MemberCount()
}

type JoinRequest struct {
	Rank           Rank
	UUID           uuid.UUID
	ControlAddr    *net.TCPAddr
	FabricURI      string
	FabricContexts uint32
	isMSRank       bool
	respCh         joinRespChan
}

type JoinResponse struct {
	Member     *Member
	Created    bool
	PrevState  MemberState
	MapVersion uint32
	joinErr    error
}

const (
	joinBatchTimeout = 250 * time.Millisecond
	joinRespTimeout  = 100 * time.Microsecond
)

// processJoinReqs is responsible for processing batches of JoinRequests. Each
// request provides a channel through which the corresponding JoinResponse is sent.
func (m *Membership) processJoinReqs(parent context.Context, reqs []*JoinRequest) {
	// Take a lock on the Membership so that we focus on processing
	// the incoming batch of JoinRequests and nothing else.
	m.Lock()
	defer m.Unlock()

	m.log.Debugf("processing %d JoinRequests", len(reqs))
	resps := make([]*JoinResponse, 0, len(reqs))
	groupUpdateShouldRun := true

	for _, req := range reqs {
		resp := new(JoinResponse)
		curMember, err := m.db.FindMemberByUUID(req.UUID)
		if err == nil {
			resp.PrevState = curMember.state
			curMember.state = MemberStateJoined
			curMember.Addr = req.ControlAddr
			curMember.FabricURI = req.FabricURI
			curMember.FabricContexts = req.FabricContexts
			resp.Member = curMember
			if err := m.db.UpdateMember(curMember); err != nil {
				resps = append(resps, &JoinResponse{joinErr: err})
				continue
			}

			resp.MapVersion, err = m.db.CurMapVersion()
			if err != nil {
				resps = append(resps, &JoinResponse{joinErr: err})
				continue
			}

			resps = append(resps, resp)
			continue
		}

		newMember := &Member{
			Rank:           req.Rank,
			UUID:           req.UUID,
			Addr:           req.ControlAddr,
			FabricURI:      req.FabricURI,
			FabricContexts: req.FabricContexts,
			state:          MemberStateJoined,
		}
		if err := m.db.AddMember(newMember); err != nil {
			resps = append(resps, &JoinResponse{joinErr: err})
			continue
		}
		resp.Created = true
		resp.Member = newMember
		resp.MapVersion, err = m.db.CurMapVersion()
		if err != nil {
			resps = append(resps, &JoinResponse{joinErr: err})
			continue
		}

		if req.isMSRank {
			groupUpdateShouldRun = false
		}
		resps = append(resps, resp)
	}

	if groupUpdateShouldRun {
		if err := m.runGroupMapUpdates(parent); err != nil {
			for i := range resps {
				resps[i] = &JoinResponse{joinErr: err}
			}
		}
	}

	for i, req := range reqs {
		ctx, cancel := context.WithTimeout(parent, joinRespTimeout)
		defer cancel()

		select {
		case <-ctx.Done():
			m.log.Errorf("failed to send join response: %s", ctx.Err())
		case req.respCh <- resps[i]:
		}
	}
	m.log.Debugf("sent %d JoinResponses", len(resps))
}

// joinLoop runs until the supplied context is canceled, and is
// responsible for receiving and processing incoming JoinRequests
// in batches.
func (m *Membership) joinLoop(ctx context.Context, repAddr *net.TCPAddr) {
	var joinReqs []*JoinRequest
	localRanksJoined := false

	for {
		select {
		case <-ctx.Done():
			return
		case jr := <-m.joinReqs:
			joinReqs = append(joinReqs, jr)
		case <-time.After(joinBatchTimeout):
			if len(joinReqs) == 0 {
				continue
			}

			var toProcess []*JoinRequest
			if localRanksJoined {
				toProcess = make([]*JoinRequest, len(joinReqs))
				copy(toProcess, joinReqs)
				joinReqs = nil
			} else {
				// This bit of hackery is needed to preferentially
				// process local ranks first, in order to get them
				// set up before processing the rest.
				var req *JoinRequest
				for i := len(joinReqs) - 1; i > 0; i-- {
					req = joinReqs[i]
					if !common.CmpTcpAddr(req.ControlAddr, repAddr) {
						continue
					}
					req.isMSRank = true
					toProcess = append(toProcess, req)
					joinReqs = append(joinReqs[:i], joinReqs[i+1:]...)
				}
				localRanksJoined = true
			}
			go m.processJoinReqs(ctx, toProcess)
		}
	}
}

// StartJoinLoop starts the loop responsible for receiving and
// processing JoinRequests in a new goroutine.
func (m *Membership) StartJoinLoop(ctx context.Context, repAddr *net.TCPAddr) {
	go m.joinLoop(ctx, repAddr)
}

// Join accepts a JoinRequest containing the new or re-joining member's details.
// Behind the scenes, the requests are batched for efficiency, but this API
// presents a synchronous interface.
func (m *Membership) Join(ctx context.Context, req *JoinRequest) (*JoinResponse, error) {
	req.respCh = make(joinRespChan)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m.joinReqs <- req:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-req.respCh:
		if resp.joinErr != nil {
			return nil, resp.joinErr
		}
		return resp, nil
	}
}

// AddOrReplace adds member to membership or replaces member if it exists.
//
// Note: this method updates state without checking if state transition is
//       legal so use with caution.
func (m *Membership) AddOrReplace(ctx context.Context, newMember *Member) error {
	m.Lock()
	defer m.Unlock()

	if err := m.addMember(ctx, newMember); err == nil {
		return nil
	}

	return m.updateMember(ctx, newMember)
}

// Remove removes member from membership, idempotent.
func (m *Membership) Remove(ctx context.Context, rank Rank) {
	m.Lock()
	defer m.Unlock()

	member, err := m.db.FindMemberByRank(rank)
	if err != nil {
		m.log.Errorf("remove %d failed: %s", rank, err)
		return
	}
	if err := m.db.RemoveMember(member); err != nil {
		m.log.Errorf("remove %d failed: %s", rank, err)
	}
}

// Get retrieves member reference from membership based on Rank.
func (m *Membership) Get(rank Rank) (*Member, error) {
	m.RLock()
	defer m.RUnlock()

	return m.db.FindMemberByRank(rank)
}

// RankList returns slice of all ordered member ranks.
func (m *Membership) RankList() ([]Rank, error) {
	return m.db.MemberRanks()
}

func (m *Membership) getHostRanks(rankSet *RankSet) map[string][]Rank {
	var rankList []Rank
	hostRanks := make(map[string][]Rank)

	if rankSet != nil {
		rankList = rankSet.Ranks()
	}

	members, err := m.db.AllMembers()
	if err != nil {
		m.log.Errorf("failed to get all members: %s", err)
		return nil
	}

	for _, member := range members {
		addr := member.Addr.String()

		if len(rankList) != 0 && !member.Rank.InList(rankList) {
			continue
		}

		if _, exists := hostRanks[addr]; exists {
			hostRanks[addr] = append(hostRanks[addr], member.Rank)
			ranks := hostRanks[addr]
			sort.Slice(ranks, func(i, j int) bool { return ranks[i] < ranks[j] })
			continue
		}
		hostRanks[addr] = []Rank{member.Rank}
	}

	return hostRanks
}

// HostRanks returns mapping of control addresses to ranks managed by harness at
// that address.
//
// Filter to include only host keys with any of the provided ranks, if supplied.
func (m *Membership) HostRanks(rankSet *RankSet) map[string][]Rank {
	m.RLock()
	defer m.RUnlock()

	return m.getHostRanks(rankSet)
}

// HostList returns slice of control addresses that contain any of the ranks
// in the input rank list.
//
// If input rank list is empty, return all hosts in membership and ignore ranks
// that are not in the membership.
func (m *Membership) HostList(rankSet *RankSet) []string {
	m.RLock()
	defer m.RUnlock()

	hostRanks := m.getHostRanks(rankSet)
	hosts := make([]string, 0, len(hostRanks))

	for host := range hostRanks {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	return hosts
}

// Members returns slice of references to all system members ordered by rank.
//
// Empty rank list implies no filtering/include all and ignore ranks that are
// not in the membership.
func (m *Membership) Members(rankSet *RankSet) (members Members) {
	m.RLock()
	defer m.RUnlock()

	if rankSet == nil || rankSet.Count() == 0 {
		var err error
		members, err = m.db.AllMembers()
		if err != nil {
			m.log.Errorf("failed to get all members: %s", err)
			return nil
		}
	} else {
		for _, rank := range rankSet.Ranks() {
			if member, err := m.db.FindMemberByRank(rank); err == nil {
				members = append(members, member)
			}
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Rank < members[j].Rank })

	return
}

// UpdateMemberStates updates member's state according to result state.
//
// If updateOnFail is false, only update member state and info if result is a
// success, if true then update state even if result is errored.
func (m *Membership) UpdateMemberStates(ctx context.Context, results MemberResults, updateOnFail bool) error {
	m.Lock()
	defer m.Unlock()

	for _, result := range results {
		member, err := m.db.FindMemberByRank(result.Rank)
		if err != nil {
			return err
		}

		// use opportunity to update host address in result
		if result.Addr == "" {
			result.Addr = member.Addr.String()
		}

		// don't update members if:
		// - result reports an error and updateOnFail is false or
		// - if transition from current to result state is illegal
		if result.Errored {
			if !updateOnFail {
				continue
			}
			if result.State != MemberStateErrored {
				return errors.Errorf(
					"errored result for rank %d has conflicting state '%s'",
					result.Rank, result.State)
			}
		}
		if member.State().isTransitionIllegal(result.State) {
			continue
		}
		member.state = result.State
		member.Info = result.Msg

		if err := m.db.UpdateMember(member); err != nil {
			return err
		}
	}

	return nil
}

// CheckRanks returns rank sets of existing and missing membership ranks from
// provided rank set string, if empty string is given then return hit rank set
// containing all ranks in the membership.
func (m *Membership) CheckRanks(ranks string) (hit, miss *RankSet, err error) {
	m.RLock()
	defer m.RUnlock()

	hit, err = CreateRankSet("")
	if err != nil {
		return
	}
	miss, err = CreateRankSet("")
	if err != nil {
		return
	}

	var rankList []Rank
	if ranks == "" {
		rankList, err = m.RankList()
		if err != nil {
			return
		}
	} else {
		rankList, err = ParseRanks(ranks)
		if err != nil {
			return
		}
	}

	for _, rank := range rankList {
		if _, err = m.db.FindMemberByRank(rank); err != nil {
			if err = miss.Add(rank); err != nil {
				return
			}
			continue
		}
		if err = hit.Add(rank); err != nil {
			return
		}
	}

	return
}

type resolveFnSig func(string, string) (*net.TCPAddr, error)

// CheckHosts returns set of all ranks on any of the hosts in provided host set
// string and another slice of all hosts from input hostset string that are
// missing from the membership.
func (m *Membership) CheckHosts(hosts string, ctlPort int, resolveFn resolveFnSig) (*RankSet, *hostlist.HostSet, error) {
	m.RLock()
	defer m.RUnlock()

	hostRanks := m.getHostRanks(nil)
	rs, err := CreateRankSet("")
	if err != nil {
		return nil, nil, err
	}

	hs, err := hostlist.CreateSet(hosts)
	if err != nil {
		return nil, nil, err
	}
	missHS, err := hostlist.CreateSet("")
	if err != nil {
		return nil, nil, err
	}
	for _, host := range strings.Split(hs.DerangedString(), ",") {
		origHostString := host
		if !common.HasPort(host) {
			host = net.JoinHostPort(host, strconv.Itoa(ctlPort))
		}

		tcpAddr, resolveErr := resolveFn("tcp", host)
		if resolveErr != nil {
			m.log.Debugf("host addr %q didn't resolve: %s", host, resolveErr)
			if _, err := missHS.Insert(origHostString); err != nil {
				return nil, nil, err
			}
			continue
		}

		if rankList, exists := hostRanks[tcpAddr.String()]; exists {
			m.log.Debugf("CheckHosts(): %v ranks found at %s", rankList, origHostString)
			for _, rank := range rankList {
				if err = rs.Add(rank); err != nil {
					return nil, nil, err
				}
			}
			continue
		}

		if _, err := missHS.Insert(origHostString); err != nil {
			return nil, nil, err
		}
	}

	return rs, missHS, nil
}

// NewMembership returns a reference to a new DAOS system membership.
func NewMembership(log logging.Logger, db *Database) *Membership {
	return &Membership{
		db:       db,
		log:      log,
		joinReqs: make(joinReqChan),
	}
}

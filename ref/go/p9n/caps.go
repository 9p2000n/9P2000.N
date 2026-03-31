package p9n

// capTable maps capability strings to bit indices.
var capTable = map[string]CapBit{
	CapTLS:         CBitTLS,
	CapAuth:        CBitAuth,
	CapCaps:        CBitCaps,
	CapAudit:       CBitAudit,
	CapCompound:    CBitCompound,
	CapLargemsg:    CBitLargemsg,
	CapCompress:    CBitCompress,
	CapZerocopy:    CBitZerocopy,
	CapCopy:        CBitCopy,
	CapAlloc:       CBitAlloc,
	CapMmap:        CBitMmap,
	CapWatch:       CBitWatch,
	CapACL:         CBitACL,
	CapSnapshot:    CBitSnapshot,
	CapXattr2:      CBitXattr2,
	CapLease:       CBitLease,
	CapSession:     CBitSession,
	CapConsistency: CBitConsistency,
	CapTopology:    CBitTopology,
	CapTrace:       CBitTrace,
	CapHealth:      CBitHealth,
	CapStats:       CBitStats,
	CapQuota:       CBitQuota,
	CapRatelimit:   CBitRatelimit,
	CapAsync:       CBitAsync,
	CapPipe:        CBitPipe,
	CapSearch:      CBitSearch,
	CapHash:        CBitHash,
	CapSpiffe:      CBitSpiffe,
	CapQUIC:        CBitQUIC,
	CapQUICMulti:   CBitQUICMulti,
	CapRDMA:        CBitRDMA,
	CapCXL:         CBitCXL,
}

// CapToBit resolves a capability string to its bit index.
// Returns -1 if the capability is unknown.
func CapToBit(cap string) int {
	if b, ok := capTable[cap]; ok {
		return int(b)
	}
	return -1
}

// CapSet tracks a set of negotiated capabilities.
type CapSet struct {
	bits uint64
	caps []string
}

// NewCapSet creates an empty capability set.
func NewCapSet() *CapSet {
	return &CapSet{}
}

// Add adds a capability to the set. Duplicates are ignored.
func (cs *CapSet) Add(cap string) {
	for _, c := range cs.caps {
		if c == cap {
			return
		}
	}
	cs.caps = append(cs.caps, cap)
	if b, ok := capTable[cap]; ok {
		cs.bits |= uint64(1) << b
	}
}

// Has returns true if the capability is in the set.
func (cs *CapSet) Has(cap string) bool {
	if b, ok := capTable[cap]; ok {
		return cs.bits&(uint64(1)<<b) != 0
	}
	for _, c := range cs.caps {
		if c == cap {
			return true
		}
	}
	return false
}

// HasBit returns true if the given capability bit is set.
func (cs *CapSet) HasBit(bit CapBit) bool {
	return cs.bits&(uint64(1)<<bit) != 0
}

// Caps returns the list of capability strings.
func (cs *CapSet) Caps() []string {
	return cs.caps
}

// Count returns the number of capabilities.
func (cs *CapSet) Count() int {
	return len(cs.caps)
}

// Intersect returns a new CapSet containing only capabilities present in both.
func Intersect(client, server *CapSet) *CapSet {
	result := NewCapSet()
	for _, c := range client.caps {
		if server.Has(c) {
			result.Add(c)
		}
	}
	return result
}

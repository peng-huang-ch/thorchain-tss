package keygen

// Request request to do keygen
type Request struct {
	Threshold   int      `json:"threshold"`
	Keys        []string `json:"keys"`
	ConsensusID string   `json:"consensus_id"`
	Version     string   `json:"tss_version"`
}

// NewRequest create a new instance of keygen.Request
func NewRequest(keys []string, consensusID string, version string) Request {
	return Request{
		Keys:        keys,
		ConsensusID: consensusID,
		Version:     version,
	}
}

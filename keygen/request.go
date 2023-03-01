package keygen

// Request request to do keygen
type Request struct {
	Threshold   int      `json:"threshold"`
	Keys        []string `json:"keys"`
	BlockHeight int64    `json:"block_height"`
	Version     string   `json:"tss_version"`
}

// NewRequest create a new instance of keygen.Request
func NewRequest(keys []string, blockHeight int64, version string) Request {
	return Request{
		Keys:        keys,
		BlockHeight: blockHeight,
		Version:     version,
	}
}

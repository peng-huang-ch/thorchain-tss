package keysign

// Request request to sign a message
type Request struct {
	PoolPubKey    string   `json:"pool_pub_key"` // pub key of the pool that we would like to send this message from
	Messages      []string `json:"messages"`     // hex encoded message to be signed
	SignerPubKeys []string `json:"signer_pub_keys"`
	ConsensusID   string   `json:"consensus_id"`
	Version       string   `json:"tss_version"`
}

func NewRequest(pk string, msgs []string, consensusID string, signers []string, version string) Request {
	return Request{
		PoolPubKey:    pk,
		Messages:      msgs,
		SignerPubKeys: signers,
		ConsensusID:   consensusID,
		Version:       version,
	}
}

package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/hashid"
)

// XXX explain why this is neccessary (Javascript typesystem,
// stable interface to use in browser, MarshalJSON in current master is broken etc.),

// SignatureData defines the JSON data which will be returned by the backend
type SignatureData struct {
	SuiteStr  string `json:"suite"`
	Filename  string `json:"filename"`
	TimeStamp string `json:"timestamp"`

	Proof      []string `json:"proof"`
	MerkleRoot string   `json:"merkleRoot"`

	Challenge string `json:"challenge"`
	Response  string `json:"response"`
	AggCommit string `json:"aggCommit"`
	AggPublic string `json:"aggPublic"`
	// TODO add Exception/Rejection mechanism as soon as it merged to master in its
	// current version (or as soon as it is finished in development)
}

type ErrorData struct {
	Error string `json:"error"`
}

func (sr *SignatureData) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Data SignatureData `json:"data"`
	}{*sr})
}

func MarshalErrorJSON(err error) ([]byte, error) {
	return json.Marshal(ErrorData{err.Error()})
}

// NewSignatureData constructs a SignatureData struct that can be marshaled to
func NewSignatureData(sig *conode.StampSignature, filename string) (*SignatureData, error) {
	prfStrings := make([]string, len(sig.Prf))
	for i, p := range []hashid.HashId(sig.Prf) {
		prfStrings[i] = b64.StdEncoding.EncodeToString(p[:])
	}
	return &SignatureData{
		sig.SuiteStr,
		filename,
		strconv.FormatInt(sig.Timestamp, 10),

		prfStrings,
		b64.StdEncoding.EncodeToString(sig.MerkleRoot[:]),
		// TODO also base64 encoded? String() might go away ... 
		sig.Challenge.String(),
		sig.Response.String(),
		sig.AggCommit.String(),
		sig.AggPublic.String(),
	}, nil
}

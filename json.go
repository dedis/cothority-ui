package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/dedis/cothority/lib/cliutils"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/proof"
	"github.com/dedis/crypto/abstract"
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

func (sr *SignatureData) ConvertToStampSignature() (*conode.StampSignature, error) {
	var err error
	proofs := make(proof.Proof, len(sr.Proof))
	for i, p := range sr.Proof {
		proofs[i], err = b64.StdEncoding.DecodeString(p)
	}
	if err != nil {
		return nil, err
	}
	var challenge abstract.Secret
	challenge, err = cliutils.ReadSecret64(suite, strings.NewReader(sr.Challenge))
	if err != nil {
		return nil, err
	}
	var response abstract.Secret
	response, err = cliutils.ReadSecret64(suite, strings.NewReader(sr.Response))
	if err != nil {
		return nil, err
	}
	var aggCommit abstract.Point
	aggCommit, err = cliutils.ReadPub64(suite, strings.NewReader(sr.AggCommit))
	if err != nil {
		return nil, err
	}
	var aggPublic abstract.Point
	aggPublic, err = cliutils.ReadPub64(suite, strings.NewReader(sr.AggPublic))
	if err != nil {
		return nil, err
	}
	var timestamp int64
	timestamp, err = strconv.ParseInt(sr.TimeStamp, 10, 64)
	var merkleRoot []byte
	merkleRoot, err = b64.StdEncoding.DecodeString(sr.MerkleRoot)
	return &conode.StampSignature{
		SuiteStr:   sr.SuiteStr,
		Timestamp:  timestamp,
		MerkleRoot: merkleRoot,
		Prf:        proofs,
		Challenge:  challenge,
		Response:   response,
		AggCommit:  aggCommit,
		AggPublic:  aggPublic,
		// TODO:
		//RejectionCommitList: make([]abstract.Point, 0),
		//RejectionPublicList: make([]abstract.Point, 0),
	}, nil
}

// NewSignatureData constructs a SignatureData struct that can be marshaled to
func NewSignatureData(sig *conode.StampSignature, filename string) (*SignatureData, error) {
	prfStrings := make([]string, len(sig.Prf))
	for i, p := range []hashid.HashId(sig.Prf) {
		prfStrings[i] = b64.StdEncoding.EncodeToString(p[:])
	}
	var challengeBuf bytes.Buffer
	if err := cliutils.WriteSecret64(suite, &challengeBuf, sig.Challenge); err != nil {
		return nil, err
	}
	var responseBuf bytes.Buffer
	if err := cliutils.WriteSecret64(suite, &responseBuf, sig.Response); err != nil {
		return nil, err
	}
	var aggCommitBuf bytes.Buffer
	if err := cliutils.WritePub64(suite, &aggCommitBuf, sig.AggCommit); err != nil {
		return nil, err
	}
	var aggPubBuf bytes.Buffer
	if err := cliutils.WritePub64(suite, &aggPubBuf, sig.AggPublic); err != nil {
		return nil, err
	}
	return &SignatureData{
		SuiteStr:  sig.SuiteStr,
		Filename:  filename,
		TimeStamp: strconv.FormatInt(sig.Timestamp, 10),

		Proof:      prfStrings,
		MerkleRoot: b64.StdEncoding.EncodeToString(sig.MerkleRoot[:]),
		Challenge:  challengeBuf.String(),
		Response:   responseBuf.String(),
		AggCommit:  aggCommitBuf.String(),
		AggPublic:  aggPubBuf.String(),
	}, nil
}

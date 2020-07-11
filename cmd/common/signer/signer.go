/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/rand"
	"encoding/pem"
	"io/ioutil"

	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	proto_utils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

// Config holds the configuration for
// creation of a Signer
type Config struct {
	MSPID        string
	IdentityPath string
	KeyPath      string
}

// Signer signs messages.
// TODO: Ideally we'd use an MSP to be agnostic, but since it's impossible to
// initialize an MSP without a CA cert that signs the signing identity,
// this will do for now.
type Signer struct {
	key     *sm2.PrivateKey
	Creator []byte
}

func (si *Signer) NewSignatureHeader() (*common.SignatureHeader, error) {
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		return nil, err
	}
	return &common.SignatureHeader{
		Creator: si.Creator,
		Nonce:   nonce,
	}, nil
}

// NewSigner creates a new Signer out of the given configuration
func NewSigner(conf Config) (*Signer, error) {
	sId, err := serializeIdentity(conf.IdentityPath, conf.MSPID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := loadPrivateKey(conf.KeyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Signer{
		Creator: sId,
		key:     key,
	}, nil
}

func serializeIdentity(clientCert string, mspID string) ([]byte, error) {
	b, err := ioutil.ReadFile(clientCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sId := &msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: b,
	}
	return proto_utils.MarshalOrPanic(sId), nil
}

func (si *Signer) Sign(msg []byte) ([]byte, error) {
	digest := util.ComputeSM3(msg)
	return signSM2(si.key, digest)
}

func loadPrivateKey(file string) (*sm2.PrivateKey, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bl, _ := pem.Decode(b)
	if bl == nil {
		return nil, errors.Errorf("failed to decode PEM block from %s", file)
	}
	key, err := sm2.ParsePKCS8UnecryptedPrivateKey(bl.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse private key from %s", file)
	}
	return key, nil
}

func signSM2(k *sm2.PrivateKey, digest []byte) ([]byte, error) {
	signature, err := k.Sign(rand.Reader, digest, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

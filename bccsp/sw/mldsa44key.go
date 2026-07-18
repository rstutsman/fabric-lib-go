/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/hyperledger/fabric-lib-go/bccsp"
)

type mldsa44PrivateKey struct {
	privKey *mldsa44.PrivateKey
}

func (k *mldsa44PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("not supported")
}

func (k *mldsa44PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	return mldsa44SKI(k.privKey.Public().(*mldsa44.PublicKey).Bytes())
}

func (k *mldsa44PrivateKey) Symmetric() bool { return false }
func (k *mldsa44PrivateKey) Private() bool   { return true }

func (k *mldsa44PrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("invalid ML-DSA-44 private key")
	}
	return &mldsa44PublicKey{pubKey: k.privKey.Public().(*mldsa44.PublicKey)}, nil
}

// CryptoPublicKey lets bccsp/signer expose non-x509 crypto.Signer keys without
// changing the stable bccsp.Key interface.
func (k *mldsa44PrivateKey) CryptoPublicKey() crypto.PublicKey {
	return k.privKey.Public()
}

type mldsa44PublicKey struct {
	pubKey *mldsa44.PublicKey
}

func (k *mldsa44PublicKey) Bytes() ([]byte, error) {
	if k.pubKey == nil {
		return nil, errors.New("invalid ML-DSA-44 public key")
	}
	return k.pubKey.Bytes(), nil
}

func (k *mldsa44PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	return mldsa44SKI(k.pubKey.Bytes())
}

func (k *mldsa44PublicKey) Symmetric() bool                   { return false }
func (k *mldsa44PublicKey) Private() bool                     { return false }
func (k *mldsa44PublicKey) PublicKey() (bccsp.Key, error)     { return k, nil }
func (k *mldsa44PublicKey) CryptoPublicKey() crypto.PublicKey { return k.pubKey }

func mldsa44SKI(raw []byte) []byte {
	digest := sha256.Sum256(raw)
	return digest[:]
}

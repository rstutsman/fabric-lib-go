/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/hyperledger/fabric-lib-go/bccsp"
)

type mldsa44Signer struct{}

func (*mldsa44Signer) Sign(k bccsp.Key, msg []byte, _ bccsp.SignerOpts) ([]byte, error) {
	key, ok := k.(*mldsa44PrivateKey)
	if !ok || key.privKey == nil {
		return nil, errors.New("invalid ML-DSA-44 private key")
	}
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(key.privKey, msg, nil, false, signature); err != nil {
		return nil, err
	}
	return signature, nil
}

type mldsa44PrivateKeyVerifier struct{}

func (*mldsa44PrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, _ bccsp.SignerOpts) (bool, error) {
	key, ok := k.(*mldsa44PrivateKey)
	if !ok || key.privKey == nil {
		return false, errors.New("invalid ML-DSA-44 private key")
	}
	publicKey := key.privKey.Public().(*mldsa44.PublicKey)
	return mldsa44.Verify(publicKey, msg, nil, signature), nil
}

type mldsa44PublicKeyVerifier struct{}

func (*mldsa44PublicKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, _ bccsp.SignerOpts) (bool, error) {
	key, ok := k.(*mldsa44PublicKey)
	if !ok || key.pubKey == nil {
		return false, errors.New("invalid ML-DSA-44 public key")
	}
	return mldsa44.Verify(key.pubKey, msg, nil, signature), nil
}

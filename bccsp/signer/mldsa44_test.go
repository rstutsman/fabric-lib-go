/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package signer

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	"github.com/stretchr/testify/require"
)

func TestMLDSA44CryptoSigner(t *testing.T) {
	csp, err := sw.NewWithParams(256, "SHA2", sw.NewDummyKeyStore())
	require.NoError(t, err)
	key, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(t, err)

	s, err := New(csp, key)
	require.NoError(t, err)
	publicKey, ok := s.Public().(*mldsa44.PublicKey)
	require.True(t, ok)

	message := []byte("message, not digest")
	signature, err := s.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, mldsa44.Verify(publicKey, message, nil, signature))
}

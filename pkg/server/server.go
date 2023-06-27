// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package server implements a test server for the KMS.
package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siderolabs/kms-client/api/kms"
	"github.com/siderolabs/kms-client/pkg/constants"
)

// Server implents gRPC API.
type Server struct {
	kms.UnimplementedKMSServiceServer

	getKey func(string) ([]byte, error)
}

// NewServer initializes new server.
func NewServer(keyHandler func(nodeUUID string) ([]byte, error)) *Server {
	return &Server{
		getKey: keyHandler,
	}
}

// Seal encrypts the incoming data.
func (srv *Server) Seal(_ context.Context, req *kms.Request) (*kms.Response, error) {
	time.Sleep(time.Second)

	key, err := srv.getKey(req.NodeUuid)
	if err != nil {
		key, err = getRandomAESKey()
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	if len(req.Data) != constants.PassphraseSize {
		return nil, status.Error(codes.InvalidArgument, "incorrect data length")
	}

	encrypted := aesgcm.Seal(nil, nonce, req.Data, nil)

	return &kms.Response{
		Data: append(nonce, encrypted...), //nolint:makezero
	}, nil
}

// Unseal decrypts the incoming data.
func (srv *Server) Unseal(_ context.Context, req *kms.Request) (*kms.Response, error) {
	time.Sleep(time.Second)

	key, err := srv.getKey(req.NodeUuid)
	if err != nil {
		key, err = getRandomAESKey()
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()

	if len(req.Data) != aes.BlockSize+constants.PassphraseSize+nonceSize {
		return nil, status.Error(codes.InvalidArgument, "incorrect data length")
	}

	resp := &kms.Response{}

	decrypted, err := aesgcm.Open(nil, req.Data[:nonceSize], req.Data[nonceSize:], nil)
	if err != nil {
		resp.Data = make([]byte, constants.PassphraseSize)

		if _, err := io.ReadFull(rand.Reader, resp.Data); err != nil {
			return nil, err
		}

		return resp, nil
	}

	resp.Data = decrypted

	return resp, nil
}

// getRandomAESKey generates random AES256 key.
func getRandomAESKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

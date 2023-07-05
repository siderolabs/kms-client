// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/siderolabs/kms-client/api/kms"
	"github.com/siderolabs/kms-client/pkg/server"
)

type ServerSuite struct {
	suite.Suite
}

func (suite *ServerSuite) TestSealUnseal() {
	key, err := server.GetRandomAESKey()
	suite.Require().NoError(err)

	passphrase := make([]byte, 32)

	_, err = io.ReadFull(rand.Reader, passphrase)
	suite.Require().NoError(err)

	srv := server.NewServer(func(_ context.Context, nodeUUID string) ([]byte, error) {
		if nodeUUID != "abcd" {
			return nil, fmt.Errorf("unknown node %s", nodeUUID)
		}

		return key, nil
	})

	ctx := context.Background()

	encrypted, err := srv.Seal(ctx, &kms.Request{
		NodeUuid: "abcd",
		Data:     passphrase,
	})

	suite.Require().NoError(err)
	suite.Require().NotEmpty(encrypted.Data)

	decrypted, err := srv.Unseal(ctx, &kms.Request{
		NodeUuid: "abcd",
		Data:     encrypted.Data,
	})

	suite.Require().NoError(err)
	suite.Require().Truef(bytes.Equal(passphrase, decrypted.Data), "expected %q to be equal to %q", passphrase, decrypted.Data)

	decrypted, err = srv.Unseal(ctx, &kms.Request{
		NodeUuid: "abce",
		Data:     encrypted.Data,
	})

	suite.Require().NoError(err)
	suite.Require().Falsef(bytes.Equal(passphrase, decrypted.Data), "expected %q not to be equal to %q", passphrase, decrypted.Data)
}

func (suite *ServerSuite) TestInvalidInputs() {
	key, err := server.GetRandomAESKey()
	suite.Require().NoError(err)

	passphrase := make([]byte, 64)

	_, err = io.ReadFull(rand.Reader, passphrase)
	suite.Require().NoError(err)

	srv := server.NewServer(func(_ context.Context, nodeUUID string) ([]byte, error) {
		if nodeUUID != "abcd" {
			return nil, fmt.Errorf("unknown node %s", nodeUUID)
		}

		return key, nil
	})

	ctx := context.Background()

	_, err = srv.Seal(ctx, &kms.Request{
		NodeUuid: "abcd",
		Data:     passphrase,
	})

	suite.Require().Error(err)

	_, err = srv.Unseal(ctx, &kms.Request{
		NodeUuid: "abcd",
		Data:     make([]byte, 0),
	})

	suite.Require().Error(err)
}

func TestServerSuite(t *testing.T) {
	suite.Run(t, new(ServerSuite))
}

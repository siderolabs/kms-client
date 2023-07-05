// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main is a simple reference implementation of the KMS server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/siderolabs/kms-client/api/kms"
	"github.com/siderolabs/kms-client/pkg/server"
)

var kmsFlags struct {
	apiEndpoint string
	keyPath     string
}

func main() {
	flag.StringVar(&kmsFlags.apiEndpoint, "kms-api-endpoint", ":4050", "gRPC API endpoint for the KMS")
	flag.StringVar(&kmsFlags.keyPath, "key-path", "", "encryption key path")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
	}
}

func run(ctx context.Context) error {
	if kmsFlags.keyPath == "" {
		return fmt.Errorf("--key-path is not set")
	}

	key, err := os.ReadFile(kmsFlags.keyPath)
	if err != nil {
		return err
	}

	srv := server.NewServer(func(context.Context, string) ([]byte, error) { return key, nil })

	s := grpc.NewServer()
	kms.RegisterKMSServiceServer(s, srv)

	lis, err := net.Listen("tcp", kmsFlags.apiEndpoint)
	if err != nil {
		return fmt.Errorf("error listening for gRPC API: %w", err)
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return s.Serve(lis)
	})

	eg.Go(func() error {
		<-ctx.Done()

		s.Stop()

		return nil
	})

	if err := eg.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}

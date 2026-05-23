package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/validator"
	server_util "github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	shutdownTimeout    = 5 * time.Second
	serverStartTimeout = 10 * time.Second
)

// Run runs spire-identity-exchange gRPC server (and optionally HTTP gateway) and waits for termination signals.
// Pass nil for a validator to disable that auth method.
func Run(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient server_util.ServerClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) {
	if err := runSpireIdentityExchangeServer(ctx, cfg, spireClient, githubOIDCValidator, k8sSATokenValidator, metrics, logger); err != nil {
		logger.Error("spire-identity-exchange error", zap.Error(err))
	} else {
		logger.Info("spire-identity-exchange server stopped gracefully")
	}
}

// runSpireIdentityExchangeServer starts the gRPC server and, if httpGatewayPort is set,
// also an HTTP/REST gateway on a separate port backed by the same in-process handler.
func runSpireIdentityExchangeServer(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient server_util.ServerClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	logger.Info("Starting spire-identity-exchange gRPC server", zap.Int("port", cfg.Server.Port))

	// Start key syncers for any validator that supports it
	for _, v := range []validator.TokenValidator{githubOIDCValidator, k8sSATokenValidator} {
		if v == nil {
			continue
		}
		if syncer, ok := v.(validator.KeySynchronizer); ok {
			logger.Info("Starting key synchronizer", zap.String("validator", fmt.Sprintf("%T", v)))
			if err := syncer.Start(ctx); err != nil {
				return fmt.Errorf("failed to start key synchronizer for %T: %w", v, err)
			}
		}
	}

	handler, err := NewGRPCHandler(spireClient, cfg, githubOIDCValidator, k8sSATokenValidator, metrics, logger)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server handler: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// --- gRPC server ---
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		return fmt.Errorf("failed to create network listener: %w", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	logger.Info("gRPC server configured with TLS",
		zap.String("cert_file", cfg.Server.TLS.CertFile),
		zap.String("key_file", cfg.Server.TLS.KeyFile))

	proto.RegisterSpireIdentityExchangeApiServer(grpcServer, handler)
	reflection.Register(grpcServer)

	errCh := make(chan error, 2)
	go func() {
		errCh <- grpcServer.Serve(listener)
	}()

	// --- HTTP gateway server (optional) ---
	var httpServer *http.Server
	if cfg.Server.HTTPGatewayPort != 0 {
		gwmux := runtime.NewServeMux()
		if err := proto.RegisterSpireIdentityExchangeApiHandlerServer(ctx, gwmux, handler); err != nil {
			return fmt.Errorf("failed to register HTTP gateway handler: %w", err)
		}
		httpServer = &http.Server{
			Addr:      fmt.Sprintf(":%d", cfg.Server.HTTPGatewayPort),
			Handler:   gwmux,
			TLSConfig: tlsConfig.Clone(),
		}
		go func() {
			if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
		logger.Info("HTTP gateway server configured with TLS",
			zap.Int("port", cfg.Server.HTTPGatewayPort),
			zap.String("cert_file", cfg.Server.TLS.CertFile),
			zap.String("key_file", cfg.Server.TLS.KeyFile))
	}

	// Give servers a moment to start; surface any immediate bind/listen errors.
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}
		return nil
	case <-time.After(serverStartTimeout):
		logger.Info("spire-identity-exchange servers started successfully",
			zap.Int("grpc_port", cfg.Server.Port),
			zap.Int("http_gateway_port", cfg.Server.HTTPGatewayPort))
	}

	select {
	case <-ctx.Done():
		logger.Info("Received shutdown signal")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		stopped := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				grpcServer.GracefulStop()
			}()
			if httpServer != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = httpServer.Shutdown(shutdownCtx)
				}()
			}
			wg.Wait()
			close(stopped)
		}()

		select {
		case <-stopped:
			logger.Info("Server shutdown completed")
		case <-shutdownCtx.Done():
			logger.Warn("Shutdown timeout exceeded, forcing stop")
			grpcServer.Stop()
		}

		return nil

	case err := <-errCh:
		return fmt.Errorf("gRPC server error: %w", err)
	}
}

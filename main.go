package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	githuboidc "github.com/spiffe/spire-identity-exchange/internal/github-oidc"
	k8ssatoken "github.com/spiffe/spire-identity-exchange/internal/k8s-sa-token"
	"github.com/spiffe/spire-identity-exchange/internal/cache"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/service"
	"github.com/spiffe/spire-identity-exchange/internal/validator"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
)

func main() {
	// Setup logger
	rawLogger, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
	defer rawLogger.Sync() //nolint:errcheck
	logger := *rawLogger

	// Parse configuration from flags
	cfg := parseFlags(&logger)

	// Create SPIRE client
	socketPath := cfg.SPIRE.UnixSocketPath
	if socketPath == "" {
		logger.Fatal("unix_socket_path is required")
	}

	spireClient, err := util.NewServerClient(&net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		logger.Fatal("failed to connect to SPIRE server via Unix socket", zap.Error(err))
	}
	defer spireClient.Release()

	// Initialize metrics (includes process and Go runtime metrics)
	metricsServer := prommetrics.NewMetricsServer(
		prommetrics.WithPort(cfg.Server.MetricsPort),
	)
	appMetrics := prommetrics.NewPluginMetrics(metricsServer.Registry, "spire_identity_exchange")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start metrics server in background
	go metricsServer.For("spire-identity-exchange", appMetrics).Start(ctx)
	logger.Info("Metrics server initialized with runtime metrics", zap.Int("port", cfg.Server.MetricsPort))

	// Create GitHub OIDC validator if enabled
	var githubOIDCValidator validator.TokenValidator
	if cfg.GitHubOIDC.Enabled {
		v, err := githuboidc.NewValidator(ctx, cfg.GitHubOIDC, appMetrics, &logger)
		if err != nil {
			logger.Fatal("failed to create GitHub OIDC validator", zap.Error(err))
		}
		githubOIDCValidator = cache.NewReplayCheckingValidator(v, cache.NewInMemoryReplayCache(ctx))
		logger.Info("GitHub OIDC validator enabled with replay cache")
	}

	// Create K8s SA token validator if enabled
	var k8sSATokenValidator validator.TokenValidator
	if cfg.K8sSAToken.Enabled {
		v, err := k8ssatoken.NewValidator(cfg.K8sSAToken.TLS, &logger)
		if err != nil {
			logger.Fatal("failed to create K8s SA token validator", zap.Error(err))
		}
		k8sSATokenValidator = v
		logger.Info("Kubernetes SA token validator enabled")
	}

	if githubOIDCValidator == nil && k8sSATokenValidator == nil {
		logger.Fatal("at least one authentication method must be enabled (githubOIDC or k8sSAToken)")
	}

	// Run the service
	service.Run(ctx, cfg, spireClient, githubOIDCValidator, k8sSATokenValidator, appMetrics, &logger)
}

func parseFlags(logger *zap.Logger) *config.SpireIdentityExchangeConfig {
	configFile := flag.String("config", "", "Path to spire-identity-exchange JSON configuration file")
	flag.Parse()

	if *configFile == "" {
		logger.Fatal("--config flag is required")
	}

	cfg, err := loadSpireIdentityExchangeConfigFile(*configFile)
	if err != nil {
		logger.Fatal("failed to load spire-identity-exchange configuration", zap.String("file", *configFile), zap.Error(err))
	}

	logger.Info("spire-identity-exchange configuration file is loaded", zap.String("file", *configFile), zap.Any("config", cfg))
	return cfg
}

// loadSpireIdentityExchangeConfigFile loads spire-identity-exchange configuration from a JSON file
func loadSpireIdentityExchangeConfigFile(filePath string) (*config.SpireIdentityExchangeConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the file %s: %w", filePath, err)
	}

	var cfg config.SpireIdentityExchangeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the file %s: %w", filePath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate the configuration: %w", err)
	}

	return &cfg, nil
}

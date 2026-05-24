// Example gRPC server that supports both TLS and mTLS on the same port.
//
// Clients without a client cert connect via TLS only.
// Clients that present a valid client cert connect via mTLS.
//
// Generate certs (self-signed, for testing only):
//
//	# CA
//	openssl genrsa -out ca.key 4096
//	openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=test-ca"
//
//	# Server cert signed by CA
//	openssl genrsa -out server.key 4096
//	openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
//	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
//
//	# Client cert signed by CA (for mTLS clients)
//	openssl genrsa -out client.key 4096
//	openssl req -new -key client.key -out client.csr -subj "/CN=test-client"
//	openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
//
// Run:
//
//	go run main.go -server-cert server.crt -server-key server.key -client-ca ca.crt
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	serverCertFile = flag.String("server-cert", "server.crt", "Server TLS certificate")
	serverKeyFile  = flag.String("server-key", "server.key", "Server TLS key")
	clientCAFile   = flag.String("client-ca", "", "CA that signed client certs; if set, mTLS is enabled for clients that present a cert")
	listenAddr     = flag.String("addr", ":8443", "Listen address")
)

func main() {
	flag.Parse()

	serverCert, err := tls.LoadX509KeyPair(*serverCertFile, *serverKeyFile)
	if err != nil {
		log.Fatalf("failed to load server cert/key: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// RequestClientCert: ask for a client cert but do not require one.
		// Connections without a client cert proceed as plain TLS.
		ClientAuth: tls.RequestClientCert,
	}

	if *clientCAFile != "" {
		pool, err := loadCertPool(*clientCAFile)
		if err != nil {
			log.Fatalf("failed to load client CA: %v", err)
		}
		tlsCfg.ClientCAs = pool
		// VerifyClientCertIfGiven: verify the cert against ClientCAs if one is
		// presented, but still allow connections that present no cert at all.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		log.Println("client CA loaded — mTLS enabled for clients that present a cert")
	} else {
		log.Println("no client CA provided — all clients use TLS only")
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(logTLSMode),
	)

	// Register your services here, e.g.:
	// pb.RegisterMyServiceServer(grpcServer, &myServiceImpl{})

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listenAddr, err)
	}

	log.Printf("server listening on %s", *listenAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// logTLSMode is a unary interceptor that logs whether the caller used TLS or mTLS.
// In a real server, use this to extract the client certificate and dispatch
// to the appropriate auth handler.
func logTLSMode(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				cert := tlsInfo.State.PeerCertificates[0]
				log.Printf("[%s] mTLS — client cert subject=%s", info.FullMethod, cert.Subject)
			} else {
				log.Printf("[%s] TLS only — no client cert", info.FullMethod)
			}
		}
	}
	return handler(ctx, req)
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates found in %s", caFile)
	}
	return pool, nil
}

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/reflect/protoreflect"

	gw "github.com/mobilecoinofficial/grpc-proxy/gen"
)

var (
	// command-line options:
	grpcServerEndpoint = flag.String("grpc-server-endpoint", "fog-ingest.alpha.mobilecoin.com:443", "gRPC server endpoint")
	grpcCertFile       = flag.String("grpc-cert-file", "", "certificate chain to use for gRPC connection")
	grpcInsecure       = flag.Bool("grpc-insecure", false, "connect to gRPC endpoint without TLS")
	httpServerListen   = flag.String("http-server-listen", ":8080", "host:port to listen on for HTTP traffic")
)

func headerMatcher(header string) (string, bool) {
	if header == "Cookie" {
		return "cookie", true
	}
	if header == "Chain-Id" {
		return "chain-id", true
	}
	return runtime.DefaultHeaderMatcher(header)
}

// Convert Grpc-Metadata-Set-Cookie headers in the GRPC response to Set-Cookie in the HTTP/1.0 response
func httpResponseModifier(ctx context.Context, w http.ResponseWriter, p protoreflect.ProtoMessage) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	if vals := md.HeaderMD.Get("set-cookie"); len(vals) > 0 {
		for _, val := range vals {
			w.Header().Add("Set-Cookie", val)
		}
	}

	return nil
}

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var pm runtime.ProtoMarshaller

	// Register gRPC server endpoint
	// Note: Make sure the gRPC server is running properly and accessible
	mux := runtime.NewServeMux(
		runtime.WithForwardResponseOption(httpResponseModifier),
		runtime.WithIncomingHeaderMatcher(headerMatcher),
		runtime.WithMarshalerOption("application/x-protobuf", &pm),
	)
	var opts []grpc.DialOption
	if *grpcInsecure {
		opts = append(opts, grpc.WithInsecure())
	} else if *grpcCertFile == "" {
		var tlsConf tls.Config
		transportCreds := credentials.NewTLS(&tlsConf)
		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	} else {
		transportCreds, err := credentials.NewClientTLSFromFile(*grpcCertFile, "")
		if err != nil {
			return err
		}

		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	}

	err := gw.RegisterConsensusClientAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterAttestedApiHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterBlockchainAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterReportAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterFogKeyImageAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterFogMerkleProofAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterFogBlockAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterFogUntrustedTxOutApiHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	err = gw.RegisterFogViewAPIHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	// Start HTTP server (and proxy calls to gRPC server endpoint)
	return http.ListenAndServe(*httpServerListen, mux)
}

func main() {
	flag.Parse()
	defer glog.Flush()

	if err := run(); err != nil {
		glog.Fatal(err)
	}
}

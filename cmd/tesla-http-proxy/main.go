package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/teslamotors/vehicle-command/internal/log"
	"github.com/teslamotors/vehicle-command/pkg/cli"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"github.com/teslamotors/vehicle-command/pkg/proxy"
	"encoding/base64"
)

const (
	cacheSize   = 10000 // Number of cached vehicle sessions
	defaultPort = 443
)

const (
	EnvTLSCert = "TESLA_HTTP_PROXY_TLS_CERT"
	EnvTLSKey  = "TESLA_HTTP_PROXY_TLS_KEY"
	EnvHost    = "TESLA_HTTP_PROXY_HOST"
	EnvPort    = "TESLA_HTTP_PROXY_PORT"
	EnvTimeout = "TESLA_HTTP_PROXY_TIMEOUT"
	EnvVerbose = "TESLA_VERBOSE"
)

const nonLocalhostWarning = `
Do not listen on a network interface without adding client authentication. Unauthorized clients may
be used to create excessive traffic from your IP address to Tesla's servers, which Tesla may respond
to by rate limiting or blocking your connections.`

type HTTProxyConfig struct {
	keyFilename  string
	certFilename string
	verbose      bool
	host         string
	port         int
	timeout      time.Duration
}

var (
	httpConfig = &HTTProxyConfig{}
)

func init() {
	flag.StringVar(&httpConfig.certFilename, "cert", "", "TLS certificate chain `file` with concatenated server, intermediate CA, and root CA certificates")
	flag.StringVar(&httpConfig.keyFilename, "tls-key", "", "Server TLS private key `file`")
	flag.BoolVar(&httpConfig.verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&httpConfig.host, "host", "localhost", "Proxy server `hostname`")
	flag.IntVar(&httpConfig.port, "port", defaultPort, "`Port` to listen on")
	flag.DurationVar(&httpConfig.timeout, "timeout", proxy.DefaultTimeout, "Timeout interval when sending commands")
}

func Usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: %s [OPTION...]\n", os.Args[0])
	fmt.Fprintf(out, "\nA server that exposes a REST API for sending commands to Tesla vehicles")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, nonLocalhostWarning)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Options:")
	flag.PrintDefaults()
}

// decodeSecretFile loads a base64 env var and writes it to a file.
// If the env var does not exist, it does nothing.
func decodeSecretFile(envVar string, path string) error {

    b64 := os.Getenv(envVar)
    if b64 == "" {
        return nil
    }

    data, err := base64.StdEncoding.DecodeString(b64)
    if err != nil {
        return fmt.Errorf("failed to decode %s: %w", envVar, err)
    }

    err = os.WriteFile(path, data, 0600)
    if err != nil {
        return fmt.Errorf("failed to write %s: %w", path, err)
    }

    return nil
}

func main() {
	// ******************************************************************************************
	// WHY IS THERE NO OPTION FOR DISABLING TLS?
	// ******************************************************************************************
	// In the past, we have had problems with third-party applications that made it easy for DIY
	// enthusiasts to inadvertently expose their vehicles to the public Internet. In order to
	// protect users who do not understand the risks of disabling TLS, we decided to omit an
	// --insecure flag or similar.
	//
	// Expert users who need to disable TLS can do so without forking this repository by using the
	// pkg/proxy package, which is agnostic to TLS. This application is a very thin wrapper around
	// that package.
    // --- Decode fly.io secrets into files ---
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Starting tesla-http-proxy...")
	
    os.Mkdir("/data", 0700)

    // TLS cert
    if err := decodeSecretFile(EnvTLSCert, "/tmp/tls-cert.pem"); err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
        os.Exit(1)
    }
	fmt.Fprintf(out, "decoded tls cert")
    
	// TLS key
    if err := decodeSecretFile(EnvTLSKey, "/tmp/tls-key.pem"); err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
        os.Exit(1)
    }
	fmt.Fprintf(out, "decoded tls key")

    // Vehicle private key (fleet key)
    if err := decodeSecretFile("TESLA_KEY_FILE", "/tmp/fleet-key.pem"); err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
        os.Exit(1)
    }
	fmt.Fprintf(out, "decoded fleet key")

    // Override environment variables so the proxy uses our decoded files
    os.Setenv(EnvTLSCert, "/tmp/tls-cert.pem")
    os.Setenv(EnvTLSKey, "/tmp/tls-key.pem")
    os.Setenv("TESLA_KEY_FILE", "/tmp/fleet-key.pem")
	fmt.Fprintf(out, "environment configured")

	// Force CLI to use file-based keyring instead of system keyrings
	os.Setenv("TESLA_KEYRING_TYPE", "file")
	os.Setenv("TESLA_KEY_FILE", "/tmp/fleet-key.pem")
	fmt.Fprintf(out, "keyring configured")

	config, err := cli.NewConfig(cli.FlagPrivateKey)
	fmt.Fprintf(out, "loaded cli config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load credential configuration: %s\n", err)
		os.Exit(1)
	}

	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}()

	flag.Usage = Usage
	config.RegisterCommandLineFlags()
	// Force -key-file flag so cli.NewConfig loads the correct file
	os.Args = append(os.Args, "-key-file", "/tmp/fleet-key.pem")
	flag.Parse()
	fmt.Fprintf(out, "parsed flags")
	err = readFromEnvironment()
	fmt.Fprintf(out, "read environment")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading environment: %s\n", err)
		os.Exit(1)
	}
	config.ReadFromEnvironment()
	fmt.Fprintf(out, "configured from environment")
	if httpConfig.verbose {
		log.SetLevel(log.LevelDebug)
	}

	// if httpConfig.host != "localhost" {
	// 	fmt.Fprintln(os.Stderr, nonLocalhostWarning)
	// }

	var skey protocol.ECDHPrivateKey
	skey, err = config.PrivateKey()
	fmt.Fprintf(out, "loaded private key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error configuring private key: %s\n", err)
		return
	}

	if tlsPublicKey, err := protocol.LoadPublicKey(httpConfig.keyFilename); err == nil {
		if bytes.Equal(tlsPublicKey.Bytes(), skey.PublicBytes()) {
			fmt.Fprintln(os.Stderr, "It is unsafe to use the same private key for TLS and command authentication.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Generate a new TLS key for this server.")
			return
		}
		log.Debug("Verified that TLS key is not the same as the command-authentication key.")
	} else {
		// Discarding the error here is deliberate
		log.Debug("Verified that TLS key is not a recycled command-authentication key, because it is not NIST P256.")
	}

	log.Debug("Creating proxy")
	fmt.Fprintf(out, "creating proxy")
	p, err := proxy.New(context.Background(), skey, cacheSize)
	if err != nil {
		log.Error("Error initializing proxy service: %v", err)
		return
	}
	p.Timeout = httpConfig.timeout
	addr := fmt.Sprintf("%s:%d", httpConfig.host, httpConfig.port)
	log.Info("Listening on %s", addr)
	fmt.Fprintf(out, "listening on %s", addr)

	// To add more application logic requests, such as alternative client authentication, create
	// a http.HandleFunc implementation (https://pkg.go.dev/net/http#HandlerFunc). The ServeHTTP
	// method of your implementation can perform your business logic and then, if the request is
	// authorized, invoke p.ServeHTTP. Finally, replace p in the below ListenAndServeTLS call with
	// an object of your newly created type.
	err = http.ListenAndServeTLS(addr, httpConfig.certFilename, httpConfig.keyFilename, p)
	fmt.Fprintf(os.Stderr, "TLS SERVER ERROR: %v\n", err)
	fmt.Fprintf(out, "server stopped\n")

}

// readConfig applies configuration from environment variables.
// Values are not overwritten.
func readFromEnvironment() error {
	if httpConfig.certFilename == "" {
		httpConfig.certFilename = os.Getenv(EnvTLSCert)
	}

	if httpConfig.keyFilename == "" {
		httpConfig.keyFilename = os.Getenv(EnvTLSKey)
	}

	if httpConfig.host == "localhost" {
		host, ok := os.LookupEnv(EnvHost)
		if ok {
			httpConfig.host = host
		}
	}

	if !httpConfig.verbose {
		if verbose, ok := os.LookupEnv(EnvVerbose); ok {
			httpConfig.verbose = verbose != "false" && verbose != "0"
		}
	}

	var err error
	if httpConfig.port == defaultPort {
		if port, ok := os.LookupEnv(EnvPort); ok {
			httpConfig.port, err = strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port: %s", port)
			}
		}
	}

	if httpConfig.timeout == proxy.DefaultTimeout {
		if timeoutEnv, ok := os.LookupEnv(EnvTimeout); ok {
			httpConfig.timeout, err = time.ParseDuration(timeoutEnv)
			if err != nil {
				return fmt.Errorf("invalid timeout: %s", timeoutEnv)
			}
		}
	}

	return nil
}

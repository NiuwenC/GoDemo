package main

import (
	"crypto/tls"
	"crypto/x509"
	"db_demo/fabric_tls/lib"
	"encoding/pem"
	"fmt"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"
)

//var DefaultCipherSuites = []uint16{
//	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
//	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
//	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
//}

const (
	tlsClientCertFile = "K:\\GoProject\\db_demo\\fabric_tls\\tls_client-cert.pem"
	tlsClientKeyFile  = "K:\\GoProject\\db_demo\\fabric_tls\\tls_client-key.pem"
	rootCertFile      = "K:\\GoProject\\db_demo\\fabric_tls\\root.pem"
)

type ClientTLSConfig struct {
	Enabled   bool     `skip:"true"`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
	Client    KeyCertFiles
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string `help:"PEM-encoded key file when mutual authentication is enabled"`
	CertFile string `help:"PEM-encoded certificate file when mutual authenticate is enabled"`
}

func main() {
	tr := new(http.Transport)
	factoryOpts := &lib.FactoryOpts{}
	csp, err := lib.InitBCCSP(&factoryOpts.CSP, "", ".")
	if err != nil {
		log.Fatal(err)
	}

	clientConfig := ClientTLSConfig{
		Enabled:   true,
		CertFiles: []string{rootCertFile},
		Client: KeyCertFiles{
			KeyFile:  tlsClientKeyFile,
			CertFile: tlsClientCertFile,
		},
	}

	if clientConfig.Enabled {
		log.Info("TLS Enabled")

		err := AbsTLSClient(&clientConfig, ".")
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig, err2 := GetClientTLSConfig(&clientConfig, csp)
		if err2 != nil {
			log.Fatal("Failed to get client TLS config: %s", err2)
		}
		// set the default ciphers
		tlsConfig.CipherSuites = lib.DefaultCipherSuites
		tr.TLSClientConfig = tlsConfig
	}
	httpClient := &http.Client{Transport: tr}
	r, err := httpClient.Get("https://localhost:7090/hello")
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)

}

func GetClientTLSConfig(cfg *ClientTLSConfig, csp bccsp.BCCSP) (*tls.Config, error) {
	var certs []tls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	log.Debugf("CA Files: %+v\n", cfg.CertFiles)
	log.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)

	if cfg.Client.CertFile != "" {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := lib.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := x509.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No trusted root certificates for TLS were provided")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read '%s'", cacert)
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, errors.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}

func checkCertDates(certFile string) error {
	log.Debug("Check client TLS certificate for valid dates")
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file '%s'", certFile)
	}

	cert, err := GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

// GetX509CertificateFromPEM get an X509 certificate from bytes in PEM format
func GetX509CertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing certificate")
	}
	return x509Cert, nil
}

func AbsTLSClient(cfg *ClientTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.CertFiles); i++ {
		cfg.CertFiles[i], err = MakeFileAbs1(cfg.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.Client.CertFile, err = MakeFileAbs1(cfg.Client.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.Client.KeyFile, err = MakeFileAbs1(cfg.Client.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}
func MakeFileAbs1(file, dir string) (string, error) {
	if file == "" {
		return "", nil
	}
	if filepath.IsAbs(file) {
		return file, nil
	}
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", errors.Wrapf(err, "Failed making '%s' absolute based on '%s'", file, dir)
	}
	return path, nil
}

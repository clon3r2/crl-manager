package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func readCERT(name string) (*x509.Certificate, error) {
	cert_file, err := os.ReadFile(name)
	if err != nil {
		fmt.Println(err.Error())
		return nil, fmt.Errorf("%v", err.Error())
	}
	block, _ := pem.Decode(cert_file)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err.Error())
		return nil, fmt.Errorf("%v", err.Error())
	}

	return cert, nil
}

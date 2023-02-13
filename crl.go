package main

import (
	"crypto/x509"
	"fmt"
	"os"
)

func readCRL(name string) (*x509.RevocationList, error) {
	crl_file, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("%v", err.Error())
	}

	crl, err := x509.ParseRevocationList(crl_file)
	if err != nil {
		return nil, fmt.Errorf("%v", err.Error())
	}

	return crl, nil
}

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
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

func checkCertIsRevoked(certificate *x509.Certificate, crl *x509.RevocationList) bool {
	var a []pkix.RevokedCertificate = crl.RevokedCertificates
	for _, cert := range a {
		if certificate.SerialNumber == cert.SerialNumber {
			fmt.Println("cert found in crl, SN == ", certificate.SerialNumber)
			return true
		}
	}
	fmt.Println("certificate is still clear.")
	return false
}

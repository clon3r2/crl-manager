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
	var revokedCerts []pkix.RevokedCertificate = crl.RevokedCertificates
	for _, revokedCert := range revokedCerts {
		if certificate.SerialNumber == revokedCert.SerialNumber {
			fmt.Println("cert found in crl, SN == ", certificate.SerialNumber)
			return true
		}
	}
	fmt.Println("certificate is still clear.")
	return false
}

// func revokeCertificate(certificate *x509.Certificate, oldCrl *x509.RevocationList) (*x509.RevocationList, error) {
// 	revokedCerts := []pkix.RevokedCertificate{
// 		{SerialNumber: certificate.SerialNumber,
// 			RevocationTime: certificate.NotAfter}}

// 	priv, err := getPrivateKeys()
// 	if err != nil {
// 		fmt.Print("error get priv key: ", err)
// 		panic(err.Error())
// 	}
// 	crl, err := x509.CreateRevocationList(rand.Reader, revokedCerts, oldCrl.Issuer, priv)
// 	return nil, nil
// }

package main

import "fmt"

func sest() {
	crl, err := readCRL("crl_out.crl")
	if err != nil {
		panic("error reading crl: " + err.Error())
	}
	certificate, err := readCERT("cert.pem")
	if err != nil {
		panic("error reading cert: " + err.Error())
	}
	fmt.Println("cert is in crl ::: ", checkCertIsRevoked(certificate, crl))
}

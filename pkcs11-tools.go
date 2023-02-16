package main

import (
	"crypto/x509"
	"fmt"

	"github.com/miekg/pkcs11"
)

const (
	TOKEN_PIN         string = "qazwsx12"
	PRIVATE_KEY_LABEL string = "a76e5a93-f726-4b12-abee-9cbe50b319ae"
	PRIVATE_KEY_ID int = 0
)

func getPrivateKeys(p *pkcs11.Ctx, session pkcs11.SessionHandle, filterParams objectFilterParams) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}

	if filterParams.Label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, filterParams.Label))
	}

	if len(filterParams.ID) != 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, filterParams.ID))
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	objects, _, err := p.FindObjects(session, 100)
	if err != nil {
		return nil, err
	}
	if err = p.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, err
	}
	if len(objects) > 1 {
		return nil, err
	}
	return objects, nil
}


func main() {
	// Open the PKCS11 library
	lib := "lib/parskey9000.so"
	p := pkcs11.New(lib)
	if p == nil {
		panic("Failed to load PKCS11 library")
	}
	defer p.Destroy()

	// Initialize the PKCS11 context
	if err := p.Initialize(); err != nil {
		panic(err)
	}
	defer p.Finalize()

	// Find the slot ID for the token
	slotList, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}
	if len(slotList) == 0 {
		panic("No slots found")
	}
	slotID := slotList[0]

	// Open a session with the token
	session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	// Login to the token
	err = p.Login(session, pkcs11.CKU_USER, TOKEN_PIN)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	// Find the private key on the token
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, PRIVATE_KEY_LABEL),
	}
	err = p.FindObjectsInit(session, template)
	if err != nil {
		panic(err)
	}
	defer p.FindObjectsFinal(session)
	obj, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("object === %v \n\n", obj)
	// Get the private key from the token
	privKey, err := p.GetAttributeValue(session, obj[0], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKO_PRIVATE_KEY, nil)})
	if err != nil {
		fmt.Println("error getattr : ", err)
		panic(err)
	}
	keyDER := privKey[0].Value
	fmt.Println("keyDer : ", keyDER)
	// Parse the private key DER
	privKeyObj, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		fmt.Println("private obj parse: ", privKeyObj)
		panic(err)
	}

	fmt.Println("rsaPrivatekey === ", privKey)
	// Convert the private key to RSA
	// rsaPrivKey, ok := privKeyObj.(*rsa.PrivateKey)
	// if !ok {
	// 	fmt.Println("error privkeyobj : ", err)
	// 	panic("Private key is not an RSA key")
	// }
	// Use the private key for signing or decryption
	// message := []byte("hello world")
	// hashed := crypto.SHA256.Sum(message)
	// signature, err := rsa.SignPKCS1v15(nil, rsaPrivKey, crypto.SHA256, hashed[:])
	// if err != nil {
	// 	panic(err)
	// }

	// // Print the signature as a PEM-encoded string
	// pemBlock := &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey),
	// }
	// fmt.Println(string(pem.EncodeToMemory(pemBlock)))
}

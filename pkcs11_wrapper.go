package main

import (
	"encoding/base64"
	"math/big"

	"github.com/miekg/pkcs11"
)

func getPrivateKeys() ([]pkcs11.ObjectHandle, error) {
	p := pkcs11.New("parskey9000.so")
	if p == nil {
		warningLogger.Println("can't create new pkcs11 context with this token library address: ")
		return nil, newAPIError("invalid token lib address", 502)
	}
	err := p.Initialize()
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't Initialize: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	defer func() {
		infoLogger.Println("cryptoki token Destroy will be called")
		p.Destroy()
	}()
	defer func() {
		infoLogger.Println("cryptoki Finalize will be called!")
		err := p.Finalize()
		if err != nil {
			errorLogger.Println("can't Finalize token")
			panic("can't Finalize token")
		}
	}()

	matchedSlot, err := getMatchedSlotID(p, "PK210843838")
	if err != nil {
		return nil, err
	}

	session, err := p.OpenSession(matchedSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't OpenSession: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}

	defer func() {
		infoLogger.Println("CloseSession will be called!")
		if err := p.CloseSession(session); err != nil {
			errorLogger.Println("can't CloseSession")
			panic("can't CloseSession")
		}
	}()

	err = p.Login(session, pkcs11.CKU_USER, "qazwsx12")
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't Login: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	defer func() {
		infoLogger.Println("Logout will be called!")
		if err := p.Logout(session); err != nil {
			errorLogger.Println("can't Logout token")
			panic("can't Logout token")
		}
	}()

	infoLogger.Println("getPrivateKeys called")
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}
	filterParams := objectFilterParams{
		Label: "a76e5a93-f726-4b12-abee-9cbe50b319ae",
		ID:    []uint8("74601abbb6f8da49ee3144c46b53858f3d8ebb95"),
	}
	if filterParams.Label != "" {
		debugLogger.Printf("add CKA_LABEL Attribute with value %s to private key template", filterParams.Label)
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, filterParams.Label))
	}

	if len(filterParams.ID) != 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, filterParams.ID))
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjectsInit: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	objects, _, err := p.FindObjects(session, 100)
	if err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjects: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjectsFinal: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	if len(objects) == 0 {
		return nil, newAPIError("private key not found", 404)
	}
	if len(objects) > 1 {
		return nil, newAPIError("more than one private key found", 406)
	}
	return objects, nil
}

func getCertificates(p *pkcs11.Ctx, session pkcs11.SessionHandle, filterParams objectFilterParams) ([]pkcs11.ObjectHandle, error) {
	infoLogger.Println("getCertificates called")
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if filterParams.Label != "" {
		debugLogger.Printf("add CKA_LABEL Attribute with value %s to certificate template", filterParams.Label)
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, filterParams.Label))
	}

	if len(filterParams.ID) != 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, filterParams.ID))
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjectsInit: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	objects, _, err := p.FindObjects(session, 100)
	if err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjects: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		errMessage := err.Error()
		errorLogger.Printf("can't FindObjectsFinal: %s", errMessage)
		return nil, newAPIError(errMessage, 502)
	}
	if len(objects) == 0 {
		return nil, newAPIError("certificate not found", 404)
	}
	if len(objects) > 1 {
		return nil, newAPIError("more than one certificate found", 406)
	}
	return objects, nil
}

func getCertInfo(p *pkcs11.Ctx, session pkcs11.SessionHandle, cert pkcs11.ObjectHandle) (certificateObject, error) {
	infoLogger.Println("getCertInfo called")
	var c certificateObject
	c.obj = cert
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(cert), template)
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't GetAttributeValue: %s", errMessage)
		return c, newAPIError(errMessage, 502)
	}
	for _, a := range attr {
		//infoLogger.Printf("attr %d, type %d, valuelen %d, value: %v\n", i, a.Type, len(a.Value), a.Value)
		//infoLogger.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))

		if a.Type == pkcs11.CKA_SUBJECT {
			// infoLogger.Println("CKA_SUBJECT !!!", i)
			/*var s asn1.RawValue
			_, err := asn1.Unmarshal(a.Value, &s)
			if err != nil {
				infoLogger.Printf("%#v\n", err.Error())
			} else {
				infoLogger.Printf("SUBJECT: %#v\n", s)
			}
			_, err = asn1.Unmarshal(s.Bytes, &s)
			if err != nil {
				infoLogger.Printf("%#v\n", err.Error())
			} else {
				infoLogger.Printf("SUB SUB: %#v\n", s)
			}
			var test asn1set
			_, err = asn1.Unmarshal(s.Bytes, &test)
			if err != nil {
				infoLogger.Printf("%#v\n", err.Error())
			} else {
				infoLogger.Printf("TEST: %#v\n", test)
			}*/
		}

		if a.Type == pkcs11.CKA_ID {
			// infoLogger.Println("#######CKA_ID !!!", i, a.Value)
			// infoLogger.Printf("CKA_ID type is: %T \n", a.Value)
			c.id = a.Value
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			c.stringifyID = mod.String()
		}

		if a.Type == pkcs11.CKA_VALUE {
			// infoLogger.Println("CKA_VALUE !!!", i)
			c.certificateRaw = base64.StdEncoding.EncodeToString(a.Value)
			//_ = ioutil.WriteFile("test.cer", a.Value, 0644)
		}

		if a.Type == pkcs11.CKA_LABEL {
			// infoLogger.Println("CKA_LABEL !!!", i)
			//infoLogger.Printf("LABEL: %s\n", string(a.Value))
			c.label = string(a.Value)
		}
	}
	return c, nil
}

func getTokensInfoForLib(tokenType string, tokenLibAddress string) []tokenInfoResponse {
	infoLogger.Println("getTokensInfoForLib called for tokenType =", tokenType)
	var res []tokenInfoResponse

	p := pkcs11.New(tokenLibAddress)
	// TODO: check how to undo New() method and release memory
	if p == nil {
		warningLogger.Println("can't create new pkcs11 context with this token library address: ", tokenLibAddress)
		return res
	}

	if err := p.Initialize(); err != nil {
		warningLogger.Printf("can't Initialize: %s", err.Error())
		return res
	}

	defer func() {
		infoLogger.Println("cryptoki Destroy will be called")
		p.Destroy()
	}()

	defer func() {
		infoLogger.Println("cryptoki Finalize will be called")
		err := p.Finalize()
		if err != nil {
			errorLogger.Println("can't Finalize token")
			panic("can't Finalize token")
		}
	}()

	slotList, err := p.GetSlotList(true)
	if err != nil {
		warningLogger.Printf("can't GetSlotList: %s", err.Error())
		return res
	}

	for _, slotID := range slotList {
		tokenInfoStruct := tokenInfoResponse{TokenType: tokenType}
		tokenInfo, err := getTokenInfo(p, slotID)
		if err != nil {
			// e := err.(*apiError)
			continue
		}
		tokenInfoStruct.SlotID = slotID
		tokenInfoStruct.SerialNumber = removeNoneAlphanumericCharacters(tokenInfo.SerialNumber)
		tokenInfoStruct.Label = removeNoneAlphanumericCharacters(tokenInfo.Label)
		tokenInfoStruct.MinPinLength = tokenInfo.MinPinLen
		tokenInfoStruct.MuxPinLength = tokenInfo.MaxPinLen
		tokenInfoStruct.Flags = tokenInfo.Flags
		res = append(res, tokenInfoStruct)
	}
	return res
}

func getTokenInfo(p *pkcs11.Ctx, slotID uint) (pkcs11.TokenInfo, error) {
	infoLogger.Println("getTokenInfo called")
	tokenInfo, err := p.GetTokenInfo(slotID)
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't GetTokenInfo: %s", errMessage)
		return pkcs11.TokenInfo{}, newAPIError(errMessage, 502)
	}
	return tokenInfo, nil
}

func getMatchedSlotID(p *pkcs11.Ctx, serialNumber string) (uint, error) {
	infoLogger.Println("getMatchedSlotID called for serialnumber =", serialNumber)
	slots, err := p.GetSlotList(true)
	if err != nil {
		errMessage := err.Error()
		warningLogger.Printf("can't GetSlotList: %s", errMessage)
		return 0, newAPIError(errMessage, 502)
	}
	for _, slotID := range slots {
		tokenInfo, err := getTokenInfo(p, slotID)
		if err != nil {
			// e := err.(*apiError)
			continue
		}
		tokenSerialNumber := removeNoneAlphanumericCharacters(tokenInfo.SerialNumber)
		if tokenSerialNumber == serialNumber {
			return slotID, nil
		}
	}
	return 0, newAPIError("no cryptoki were found with this serial number", 404)
}

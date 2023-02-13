package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

type signPayload struct {
	PinCode   string `json:"pincode"`
	Content   string `json:"content"`
	Mechanism uint   `json:"mechanism"`
}

type decryptPayload struct {
	PinCode          string `json:"pincode"`
	EncryptedContent string `json:"encrypted_content"`
	Mechanism        uint   `json:"mechanism"`
}

type standardSignResponse struct {
	Signature   string `json:"signature"`
	Certificate string `json:"certificate"`
}

type standardDecryptResponse struct {
	Content string `json:"content"`
}

type tokenInfoResponse struct {
	TokenType    string `json:"token_type"` // "parskey_pk9000",
	SlotID       uint   `json:"slot_id"`
	SerialNumber string `json:"serial_number"`
	Label        string `json:"label"`
	MinPinLength uint   `json:"min_pin_length"`
	MuxPinLength uint   `json:"max_pin_length"`
	Flags        uint   `json:"flags"`
}

type notFoundResponse struct {
	Detail string `json:"detail"`
}

type certificateObject struct {
	obj            pkcs11.ObjectHandle
	label          string
	id             []byte
	stringifyID    string
	certificateRaw string
}

type objectFilterParams struct {
	Label string
	ID    []uint8
}

type slotList []uint

func (e *apiError) Error() string {
	return fmt.Sprintf("%d - %s - %s", e.StatusCode, e.Pkcs11, e.Message)
}

type apiError struct {
	Message    string `json:"message"`
	StatusCode int    `json:"http_status_code"`
	Pkcs11     string `json:"pkcs11_error_code"`
}

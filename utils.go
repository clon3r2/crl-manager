package main

import (
	"io/ioutil"
	"regexp"
	"strings"
)

func getTokenLibs() (map[string]string, error) {
	configMap := make(map[string]string)
	byteSliceContent, err := ioutil.ReadFile("go_token_driver_config.cfg")
	if err != nil {
		return nil, newAPIError("'go_token_driver_config.cfg' not found.", 503)
	}
	byteSliceContentString := strings.Split(string(byteSliceContent), "\n")
	for _, line := range byteSliceContentString {
		if len(line) == 0 {
			continue
		}
		if !strings.ContainsAny(line, "=") {
			continue
		}
		lineSlices := strings.Split(line, "=")
		configMap[lineSlices[0]] = lineSlices[1]
	}
	return configMap, nil
}

func newAPIError(errorMessage string, statusCode int) error {
	var pkcs11Hex string
	if strings.HasPrefix(errorMessage, "pkcs11") {
		errorSlices := strings.Split(errorMessage, ": ")
		// TODO if len() == 3 do
		pkcs11Hex = errorSlices[1]
		errorMessage = errorSlices[2]
	}

	return &apiError{Message: errorMessage, StatusCode: statusCode, Pkcs11: pkcs11Hex}
}

func removeNoneAlphanumericCharacters(unprocessedString string) string {
	// Make a Regex to say we only want letters and numbers
	regularExpresion := regexp.MustCompile("[^a-zA-Z0-9]+")
	processedString := regularExpresion.ReplaceAllString(unprocessedString, "")

	return processedString
}

func checkPinCodeDifficulty(pincode string) error {
	infoLogger.Println("checkPinCodeDifficulty called")
	var alphabetRegex = regexp.MustCompile(`[a-zA-Z]`)
	var numericRegex = regexp.MustCompile(`[0-9]`)

	if alphabetRegex.MatchString(pincode) && numericRegex.MatchString(pincode) {
		return nil
	}
	return newAPIError("Are you sure you entered the correct PIN? If so, change your PIN from token manager so that it contains both numbers and alphabets, then try again.", 400)
}

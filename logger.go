package main

import (
	"log"
	"os"
)

var (
	warningLogger *log.Logger
	infoLogger    *log.Logger
	errorLogger   *log.Logger
	debugLogger   *log.Logger
)

func initializeLog() {
	file, err := os.OpenFile("go_token_driver.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	infoLogger = log.New(file, "INFO: ", log.LstdFlags|log.Lshortfile)
	warningLogger = log.New(file, "WARNING: ", log.LstdFlags|log.Lshortfile)
	errorLogger = log.New(file, "ERROR: ", log.LstdFlags|log.Lshortfile)
	debugLogger = log.New(file, "DEBUG: ", log.LstdFlags|log.Lshortfile)
}

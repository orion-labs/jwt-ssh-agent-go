package agentjwt

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
)

type TestServer struct {
	Address    string
	Port       int
	PubkeyFunc func(username string) (pubkey string, err error)
}

// Run runs the test server.
func (d *TestServer) RunTestServer() (err error) {
	log.Printf("Running test server on %s port %d.", d.Address, d.Port)

	fullAddress := fmt.Sprintf("%s:%s", d.Address, strconv.Itoa(d.Port))

	http.HandleFunc("/", d.RootHandler)

	err = http.ListenAndServe(fullAddress, nil)

	return err
}

func (d *TestServer) RootHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Token")

	// Parse the token, which includes setting up it's internals so it can be verified.
	subject, token, err := ParsePubkeySignedToken(tokenString, d.PubkeyFunc)
	if err != nil {
		log.Printf("Error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		log.Printf("Auth Failed")
		w.WriteHeader(http.StatusUnauthorized)
	}

	log.Printf("Subject %s successfuly authenticated", subject)
}

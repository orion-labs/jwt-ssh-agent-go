/*

Copyright 2020 Orionlabs, Inc orionlabs.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

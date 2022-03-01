package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/fajarabdillahfn/banking_auth/dto"
	"github.com/fajarabdillahfn/banking_auth/service"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) NotImplementedHandle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Handler not implemented...")
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		log.Println("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Login(loginRequest)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, err.Error())
		} else {
			fmt.Fprintf(w, *token)
		}
	}
}

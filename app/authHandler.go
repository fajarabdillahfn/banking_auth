package app

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/fajarabdillahfn/banking_auth/dto"
	"github.com/fajarabdillahfn/banking_auth/service"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		log.Println("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Login(loginRequest)
		if err != nil {
			writeResponse(w, http.StatusUnauthorized, err.Error())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	// converting from query to map
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		err := h.service.Verify(urlParams)
		if err != nil {
			writeResponse(w, http.StatusOK, notAuthorizedResponse(err.Error()))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}
}

func (h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		log.Println("Error while decoding refresh token request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Refresh(refreshRequest)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, err.Error())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

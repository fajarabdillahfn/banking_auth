package app

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fajarabdillahfn/banking-lib/logger"
	"github.com/fajarabdillahfn/banking_auth/domain"
	"github.com/fajarabdillahfn/banking_auth/service"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"

	_ "github.com/lib/pq"
)

func Start() {
	// sanityCheck()
	router := mux.NewRouter()
	authRepository := domain.NewAuthRepositoryDb(getDbClient())
	ah := AuthHandler{service: service.NewLoginService(authRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/refresh", ah.Refresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	address := "localhost"
	port := ":8181"
	logger.Info(fmt.Sprintf("Starting OAuth server on %s:%s ...", address, port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router))
}

func getDbClient() *sqlx.DB {
	client, err := sqlx.Open("postgres", "postgres://abdillah.fajar:masBed0311@localhost/banking_app?sslmode=disable")
	if err != nil {
		panic(err)
	}

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	return client
}

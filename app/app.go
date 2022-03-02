package app

import (
	"log"
	"net/http"
	"time"

	"github.com/fajarabdillahfn/banking_auth/domain"
	"github.com/fajarabdillahfn/banking_auth/service"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"

	_ "github.com/lib/pq"
)

// func sanityCheck() {
// 	if os.Getenv("SERVER_ADDRESS") == "" ||
// 		os.Getenv("SERVER_PORT") == "" {
// 		log.Fatal("Environment variable not defined....")
// 	}
// }

func Start() {
	// sanityCheck()
	router := mux.NewRouter()
	authRepository := domain.NewAuthRepositoryDb(getDbClient())
	ah := AuthHandler{service: service.NewLoginService(authRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	log.Fatal(http.ListenAndServe(":8080", router))
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

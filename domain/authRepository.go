package domain

import (
	"database/sql"
	"errors"
	"log"

	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	FindBy(string, string) (*Login, error)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, error)
	RefreshTokenExists(refreshToken string) error
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client: dbClient}
}

func (d AuthRepositoryDb) FindBy(username, password string) (*Login, error) {
	var login Login

	sqlVerify := `SELECT username, u.customer_id, role, array_to_string(array_agg(a.account_id), ',') as account_numbers FROM users u
				  LEFT JOIN accounts a ON a.customer_id = u.customer_id
				  WHERE username = $1 AND password = $2
				  GROUP BY username, u.customer_id`

	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid credentials")
		} else {
			log.Println("Error while verifying login request from database: " + err.Error())
			return nil, errors.New("unexpected database error")
		}
	}

	return &login, nil
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) error {
	sqlSelect := "SELECT refresh_token from refresh_token_store where refresh_token = $1"

	var token string

	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("refresh token not registered in the store")
		} else {
			log.Println("Unexpected database error: " + err.Error())
			return errors.New("unexpected database error")
		}
	}

	return nil
}

func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, error) {
	var refreshToken string
	var err error

	if refreshToken, err = authToken.NewRefreshToken(); err != nil {
		return "", err
	}

	// store it in the store
	sqlInsert := "INSERT INTO refresh_token_store (refresh_token) values ($1)"
	_, err = d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		log.Println("unexpected database error: " + err.Error())
		return "", errors.New("unexpected database error")
	}
	return refreshToken, nil
}

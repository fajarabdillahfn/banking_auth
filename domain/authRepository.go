package domain

import (
	"database/sql"

	"github.com/fajarabdillahfn/banking-lib/errs"
	"github.com/fajarabdillahfn/banking-lib/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	FindBy(string, string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client: dbClient}
}

func (d AuthRepositoryDb) FindBy(username, password string) (*Login, *errs.AppError) {
	var login Login

	sqlVerify := `SELECT username, u.customer_id, role, array_to_string(array_agg(a.account_id), ',') as account_numbers FROM users u
				  LEFT JOIN accounts a ON a.customer_id = u.customer_id
				  WHERE username = $1 AND password = $2
				  GROUP BY username, u.customer_id`

	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("unexpected database error")
		}
	}

	return &login, nil
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "SELECT refresh_token from refresh_token_store where refresh_token = $1"

	var token string

	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}

	return nil
}

func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	var refreshToken string
	var appErr *errs.AppError

	if refreshToken, appErr = authToken.NewRefreshToken(); appErr != nil {
		return "", appErr
	}

	// store it in the store
	sqlInsert := "INSERT INTO refresh_token_store (refresh_token) values ($1)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}

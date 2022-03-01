package dto

type LoginRequest struct {
	Username string `db:"username"`
	Password string `db:"password"`
}
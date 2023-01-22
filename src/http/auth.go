package http

import (
	"encoding/json"
	"finance-api/src/db"
	"net/http"

	"github.com/joshk418/golactus"
)

func (s *Service) LoginUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var user *db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	return s.app.LoginUser(ctx, user)
}

func (s *Service) LogoutUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var user *db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	return nil, s.app.LogoutUser(ctx, user.EmailAddress)
}

func (s *Service) RegisterUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var user *db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	return nil, s.app.RegisterUser(ctx, user)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Service) RefreshToken(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var req *RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	return s.app.RefreshToken(ctx, req.RefreshToken)
}

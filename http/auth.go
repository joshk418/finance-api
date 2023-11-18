package http

import (
	"encoding/json"
	"finance-api/db"
	"net/http"

	"github.com/joshk418/golactus"
)

func (s *Service) LoginUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var user *db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	accessToken, refreshToken, err := s.app.LoginUser(ctx, user)
	if err != nil {
		return nil, err
	}

	s.setRefreshTokenCookie(w, refreshToken)

	return accessToken, nil
}

func (s *Service) LogoutUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID, ok := r.Context().Value(UserIDContextKey).(int)
	if !ok {
		return nil, golactus.NewError(http.StatusInternalServerError, "Could not get userID")
	}

	return nil, s.app.LogoutUser(ctx, userID)
}

func (s *Service) RegisterUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	var user *db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, golactus.NewError(http.StatusUnprocessableEntity, "json is invalid")
	}

	return nil, s.app.RegisterUser(ctx, user)
}

func (s *Service) RefreshToken(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	cookie, err := r.Cookie("Refresh-Token")
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, golactus.NewError(http.StatusNotFound, err)
		}
		return nil, golactus.NewError(http.StatusBadRequest, err)
	}

	token, err := s.app.RefreshToken(ctx, cookie.Value)
	if err != nil {
		return nil, err
	}

	s.setRefreshTokenCookie(w, token)

	return nil, nil
}

func (s *Service) setRefreshTokenCookie(w http.ResponseWriter, encryptedTokenID string) {
	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		Name:     "Refresh-Token",
		Value:    encryptedTokenID,
	})
}

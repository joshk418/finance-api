package http

import (
	"errors"
	"finance-api/src/app"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
)

var (
	ignoredUrls = []string{"/finance/auth/login", "/finance/auth/register"}
)

func (s *Service) CheckAuthorizationMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, url := range ignoredUrls {
			if strings.Contains(strings.ToLower(r.RequestURI), strings.ToLower(url)) {
				h.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			handleHttpError(w, http.StatusUnauthorized, errors.New("missing authorization header"))
			return
		}

		if strings.HasPrefix(strings.ToLower(authHeader), "bearer") {
			authHeader = authHeader[len("bearer "):]
		}

		claims := &app.AccessTokenClaims{}

		tkn, err := jwt.ParseWithClaims(authHeader, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(s.cfg.JwtKey), nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				handleHttpError(w, http.StatusUnauthorized, err)
				return
			}

			handleHttpError(w, http.StatusBadRequest, err)
			return
		}

		if !tkn.Valid {
			handleHttpError(w, http.StatusUnauthorized, errors.New("invalid token"))
			return
		}

		if claims.UserID == 0 || claims.AuthUUID == "" {
			handleHttpError(w, http.StatusUnauthorized, errors.New("invalid claims"))
			return
		}

		userToken, err := s.app.UserTokenByUserIDAndAuthUUID(r.Context(), claims.UserID, claims.AuthUUID)
		if err != nil {
			handleHttpError(w, http.StatusInternalServerError, err)
			return
		}

		if userToken == nil {
			handleHttpError(w, http.StatusUnauthorized, errors.New("no user_token record found"))
			return
		}

		h.ServeHTTP(w, r)
	})
}

func handleHttpError(w http.ResponseWriter, code int, err error) {
	log.Error(err)
	w.WriteHeader(code)
}

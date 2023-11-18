package http

import (
	"context"
	"errors"
	"finance-api/app"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
)

var (
	ignoredAuthUrls = []string{"/finance/auth/login", "/finance/auth/register", "/finance/auth/refresh"}
)

type ContextKey string

const (
	UserIDContextKey = ContextKey("UserID")
)

func (s *Service) CheckAuthorizationMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, url := range ignoredAuthUrls {
			if strings.Contains(strings.ToLower(r.RequestURI), strings.ToLower(url)) {
				h.ServeHTTP(w, r)
				return
			}
		}

		ctx := r.Context()

		authHeader, code, err := parseAuthHeader(r)
		if err != nil {
			handleHttpError(w, code, err)
			return
		}

		claims, code, err := s.parseAndCheckToken(ctx, authHeader)
		if err != nil {
			handleHttpError(w, code, err)
			return
		}

		if code, err := s.checkUserTokenRecord(ctx, claims.UserID, claims.AuthUUID); err != nil {
			handleHttpError(w, code, err)
			return
		}

		h.ServeHTTP(w, r.WithContext(context.WithValue(ctx, UserIDContextKey, claims.UserID)))
	})
}

func (s *Service) checkUserTokenRecord(ctx context.Context, userID int, uuid string) (int, error) {
	if userID == 0 || uuid == "" {
		return http.StatusUnauthorized, errors.New("invalid claims")
	}

	userToken, err := s.app.UserTokenByUserIDAndAuthUUID(ctx, userID, uuid)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if userToken == nil {
		return http.StatusUnauthorized, errors.New("no user_token record found")
	}

	return 0, nil
}

func (s *Service) parseAndCheckToken(ctx context.Context, authHeader string) (*app.TokenClaims, int, error) {
	claims := &app.TokenClaims{}

	tkn, err := jwt.ParseWithClaims(authHeader, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.cfg.JwtKey), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, http.StatusUnauthorized, err
		}

		if strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) && (claims.UserID != 0 && claims.AuthUUID != "") {
			if err := s.app.DeleteUserTokenByUserIDAndAuthUUID(ctx, claims.UserID, claims.AuthUUID); err != nil {
				return nil, http.StatusInternalServerError, err
			}
		}

		return nil, http.StatusBadRequest, err
	}

	if !tkn.Valid {
		return nil, http.StatusUnauthorized, errors.New("invalid token")
	}

	return claims, 0, nil
}

func parseAuthHeader(r *http.Request) (string, int, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", http.StatusUnauthorized, errors.New("missing authorization header")
	}

	if strings.HasPrefix(strings.ToLower(authHeader), "bearer") {
		authHeader = authHeader[len("bearer "):]
	}

	return authHeader, 0, nil
}

func handleHttpError(w http.ResponseWriter, code int, err error) {
	log.Error(err)
	w.WriteHeader(code)
}

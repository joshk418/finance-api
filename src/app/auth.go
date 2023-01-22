package app

import (
	"context"
	"finance-api/src/db"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/joshk418/golactus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type Token struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func (s *Service) LoginUser(ctx context.Context, user *db.User) (*Token, error) {
	hash, err := s.db.UserPasswordHashByEmailAddress(ctx, user.EmailAddress)
	if err != nil {
		return nil, err
	}

	if !checkPasswordHash(user.Password, hash) {
		return nil, golactus.NewError(http.StatusBadRequest, "Invalid login credentials")
	}

	emailUser, err := s.db.UserByEmailAddress(ctx, user.EmailAddress)
	if err != nil {
		return nil, err
	}

	if err := s.db.DeleteUserTokensByUserID(ctx, emailUser.UserID); err != nil {
		return nil, err
	}

	return s.generateTokenPair(ctx, emailUser)
}

func (s *Service) LogoutUser(ctx context.Context, emailAddress string) error {
	emailUser, err := s.db.UserByEmailAddress(ctx, emailAddress)
	if err != nil {
		return err
	}

	return s.db.DeleteUserTokensByUserID(ctx, emailUser.UserID)
}

func (s *Service) RegisterUser(ctx context.Context, user *db.User) error {
	if err := user.Validate(); err != nil {
		return err
	}

	emailUser, err := s.UserByEmailAddress(ctx, user.EmailAddress)
	if err != nil {
		return err
	}

	if emailUser != nil {
		return golactus.NewError(http.StatusBadRequest, "User found with same email address")
	}

	hash, err := hashPassword(user.Password)
	if err != nil {
		return golactus.NewError(http.StatusBadRequest, "Password is invalid")
	}

	user.Password = hash

	if _, err := s.SaveUser(ctx, user); err != nil {
		return err
	}

	return nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	claims := &TokenClaims{}
	_, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtkey, nil
	})
	if err != nil {
		if strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) && (claims.UserID != 0 && claims.AuthUUID != "") {
			if err := s.DeleteUserTokenByUserIDAndAuthUUID(ctx, claims.UserID, claims.AuthUUID); err != nil {
				return nil, golactus.NewError(http.StatusInternalServerError, err)
			}
		}

		return nil, golactus.NewError(http.StatusUnauthorized, "Refresh token is invalid")
	}

	user, err := s.db.UserByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.db.DeleteUserTokensByUserID(ctx, user.UserID); err != nil {
		return nil, err
	}

	return s.generateTokenPair(ctx, user)
}

type TokenClaims struct {
	UserID   int    `json:"userID"`
	AuthUUID string `json:"authUUID"`
	jwt.RegisteredClaims
}

func (s *Service) generateTokenPair(ctx context.Context, user *db.User) (*Token, error) {
	accessAuthUuid := uuid.New()
	accessTokenClaims := &TokenClaims{
		UserID:   user.UserID,
		AuthUUID: accessAuthUuid.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	accessToken, err := s.generateToken(ctx, accessTokenClaims)
	if err != nil {
		return nil, err
	}

	refreshAuthUuid := uuid.New()
	refreshTokenClaims := &TokenClaims{
		UserID:   user.UserID,
		AuthUUID: refreshAuthUuid.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	refreshToken, err := s.generateToken(ctx, refreshTokenClaims)
	if err != nil {
		return nil, err
	}

	t := &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	userToken := &db.UserToken{UserID: user.UserID, AuthUUID: accessAuthUuid.String(), Type: db.AccessTokenType}
	if _, err := s.db.SaveUserToken(ctx, userToken); err != nil {
		return nil, err
	}

	userRefreshToken := &db.UserToken{UserID: user.UserID, AuthUUID: refreshAuthUuid.String(), Type: db.RefreshType}
	if _, err := s.db.SaveUserToken(ctx, userRefreshToken); err != nil {
		return nil, err
	}

	return t, nil
}

func (s *Service) generateToken(ctx context.Context, claim jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	tokenString, err := token.SignedString(s.jwtkey)
	if err != nil {
		log.Error(err)
		return "", golactus.NewError(http.StatusInternalServerError, "Could not create token")
	}

	return tokenString, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

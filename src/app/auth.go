package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"finance-api/src/db"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/joshk418/golactus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type Token struct {
	AccessToken string `json:"accessToken"`
}

func (s *Service) LoginUser(ctx context.Context, user *db.User) (*Token, string, error) {
	hash, err := s.db.UserPasswordHashByEmailAddress(ctx, user.EmailAddress)
	if err != nil {
		return nil, "", err
	}

	if !checkPasswordHash(user.Password, hash) {
		return nil, "", golactus.NewError(http.StatusBadRequest, "Invalid login credentials")
	}

	emailUser, err := s.db.UserByEmailAddress(ctx, user.EmailAddress)
	if err != nil {
		return nil, "", err
	}

	if err := s.db.DeleteRefreshTokensByUserID(ctx, emailUser.UserID); err != nil {
		return nil, "", err
	}

	if err := s.db.DeleteUserTokensByUserID(ctx, emailUser.UserID); err != nil {
		return nil, "", err
	}

	refreshToken, err := s.generateRefreshToken(ctx, emailUser)
	if err != nil {
		return nil, "", err
	}

	accessToken, err := s.generateAccessToken(ctx, emailUser)
	if err != nil {
		return nil, "", err
	}

	return accessToken, refreshToken, nil
}

func (s *Service) LogoutUser(ctx context.Context, userID int) error {
	user, err := s.db.UserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.db.DeleteUserTokensByUserID(ctx, user.UserID); err != nil {
		return err
	}

	return s.db.DeleteRefreshTokensByUserID(ctx, user.UserID)
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

func (s *Service) RefreshToken(ctx context.Context, encryptedRefreshToken string) (string, error) {
	refreshTokenID, err := decryptTokenID(encryptedRefreshToken, s.encryptionKey)
	if err != nil {
		return "", err
	}

	token, err := s.db.RefreshTokenByID(ctx, refreshTokenID)
	if err != nil {
		return "", err
	}

	claims := &RefreshTokenClaims{}
	_, err = jwt.ParseWithClaims(token.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtkey, nil
	})
	if err != nil {
		if strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) && (refreshTokenID != 0) {
			if err := s.db.DeleteRefreshTokenByID(ctx, claims.UserID, refreshTokenID); err != nil {
				return "", golactus.NewError(http.StatusInternalServerError, err)
			}
		}

		return "", golactus.NewError(http.StatusUnauthorized, "Refresh token is invalid")
	}

	user, err := s.db.UserByID(ctx, claims.UserID)
	if err != nil {
		return "", err
	}

	if err := s.db.DeleteRefreshTokensByUserID(ctx, user.UserID); err != nil {
		return "", err
	}

	return s.generateRefreshToken(ctx, user)
}

type TokenClaims struct {
	UserID   int    `json:"userID"`
	AuthUUID string `json:"authUUID"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UserID int `json:"userID"`
	jwt.RegisteredClaims
}

func (s *Service) generateAccessToken(ctx context.Context, user *db.User) (*Token, error) {
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

	t := &Token{
		AccessToken: accessToken,
	}

	userToken := &db.UserToken{UserID: user.UserID, AuthUUID: accessAuthUuid.String(), Type: db.AccessTokenType}
	if _, err := s.db.SaveUserToken(ctx, userToken); err != nil {
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

func (s *Service) generateRefreshToken(ctx context.Context, user *db.User) (string, error) {
	refreshTokenClaims := &TokenClaims{
		UserID: user.UserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	refreshToken, err := s.generateToken(ctx, refreshTokenClaims)
	if err != nil {
		return "", err
	}

	token := &db.RefreshToken{
		Token:  refreshToken,
		UserID: user.UserID,
	}

	id, err := s.db.SaveRefreshToken(ctx, token)
	if err != nil {
		return "", err
	}

	return encryptTokenID(id, s.encryptionKey)
}

var (
	encryptionBytes = []byte{99, 46, 57, 24, 84, 35, 25, 72, 87, 35, 88, 98, 66, 32, 14, 05}
)

func encryptTokenID(tokenID int, encryptionKey []byte) (string, error) {
	tokenIDStr := strconv.Itoa(tokenID)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return "", golactus.NewError(http.StatusInternalServerError, "Failed to encrypt token")
	}

	plainText := []byte(tokenIDStr)
	cfb := cipher.NewCFBEncrypter(block, encryptionBytes)

	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decryptTokenID(text string, encryptionKey []byte) (int, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return 0, golactus.NewError(http.StatusInternalServerError, "Failed to decode token")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return 0, err
	}

	cfb := cipher.NewCFBDecrypter(block, encryptionBytes)
	plainText := make([]byte, len(data))
	cfb.XORKeyStream(plainText, data)

	return strconv.Atoi(string(plainText))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

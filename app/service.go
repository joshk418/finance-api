package app

import (
	"finance-api/db"
)

type Service struct {
	db            *db.Service
	jwtkey        []byte
	encryptionKey []byte
}

func New(connection, jwtkey, encryptionKey string) (*Service, error) {
	s, err := db.New(connection)
	if err != nil {
		return nil, err
	}

	return &Service{s, []byte(jwtkey), []byte(encryptionKey)}, nil
}

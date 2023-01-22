package app

import (
	"finance-api/src/db"
)

type Service struct {
	db     *db.Service
	jwtkey []byte
}

func New(connection, jwtkey string) (*Service, error) {
	s, err := db.New(connection)
	if err != nil {
		return nil, err
	}

	return &Service{s, []byte(jwtkey)}, nil
}

package http

import (
	"finance-api/src/app"

	"github.com/joshk418/golactus"

	_ "github.com/lib/pq"
)

type Service struct {
	app    *app.Service
	cfg    *Config
	server *golactus.Server
}

type Config struct {
	Name           string
	Host           string
	Port           string
	JwtKey         string
	EncryptionKey  string
	DbConnection   string
	RequestTimeout int
}

func New(cfg *Config) (*Service, error) {
	a, err := app.New(cfg.DbConnection, cfg.JwtKey, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	server := &Service{app: a, cfg: cfg}
	server.setup()

	return server, nil
}

func (s *Service) Serve() error {
	return s.server.Serve()
}

func (s *Service) setup() *Service {
	server := golactus.NewServer(
		golactus.Name(s.cfg.Name),
		golactus.Host(s.cfg.Host),
		golactus.Port(s.cfg.Port),
		golactus.RequestTimeout(s.cfg.RequestTimeout),
	)

	server.AddRoutes(
		golactus.Post("/auth/login", s.LoginUser),
		golactus.Post("/auth/logout", s.LogoutUser),
		golactus.Post("/auth/register", s.RegisterUser),
		golactus.Post("/auth/refresh", s.RefreshToken),

		golactus.Get("/users/{userID}", s.UserByID),
	)

	server.RegisterMiddleware(s.CheckAuthorizationMiddleware)

	s.server = server

	return s
}

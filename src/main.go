package main

import (
	httpd "finance-api/src/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/BurntSushi/toml"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Fatal(startServer())
}

func startServer() error {
	cfg, err := readConfig()
	if err != nil {
		return err
	}

	httpService, err := httpd.New(cfg)
	if err != nil {
		return err
	}

	return httpService.Serve()
}

func readConfig() (*httpd.Config, error) {
	file, err := os.ReadFile("finance-api.toml")
	if err != nil {
		return nil, err
	}

	var cfg *httpd.Config
	if err := toml.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

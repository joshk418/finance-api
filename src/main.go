package main

import (
	httpd "finance-api/src/http"
	"flag"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/BurntSushi/toml"
)

var (
	cfgFlag = flag.String("cfg", "", "config for server")
)

func main() {
	flag.Parse()

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
	fileName := *cfgFlag
	if !strings.Contains(fileName, ".toml") {
		fileName += ".toml"
	}

	file, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var cfg *httpd.Config
	if err := toml.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

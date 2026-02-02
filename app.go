package main

import (
	"fmt"
	"io"
	"os"
)

type App struct {
	cfg     *Config
	source  IPSource
	outFile io.Writer
}

func NewApp(cfg *Config) (*App, error) {
	source, err := newIPSource(cfg)
	if err != nil {
		return nil, err
	}

	app := &App{
		cfg:    cfg,
		source: source,
	}

	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		app.outFile = f
	}

	return app, nil
}

func newIPSource(cfg *Config) (IPSource, error) {
	if cfg.InputFile != "" {
		return NewFileSource(cfg.InputFile)
	}
	if cfg.Mode == "list" {
		return NewDNSListSource(cfg.DataDir, cfg.Country)
	}
	return NewCIDRSource(cfg.DataDir, cfg.Country, cfg.Mode)
}

func (a *App) Close() {
	if f, ok := a.outFile.(*os.File); ok && f != nil {
		f.Close()
	}
}

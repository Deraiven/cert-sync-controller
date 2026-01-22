package config

import (
	"time"
)

type Config struct {
	Kong       KongConfig       `yaml:"kong"`
	Controller ControllerConfig `yaml:"controller"`
	Logging    LoggingConfig    `yaml:"log"`
}

type KongConfig struct {
	AdminURL   string `yaml:"adminUrl"`
	AdminToken string `yaml:"adminToken,omitempty"`
}

type ControllerConfig struct {
	WatchNamespace string        `yaml:"watchNamespace"`
	LabelSelector  string        `yaml:"labelSelector,omitempty"`
	ResyncPeriod   time.Duration `yaml:"resyncPeriod"`
	ClusterName    string        `yaml:"clusterName"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

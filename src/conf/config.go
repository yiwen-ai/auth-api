package conf

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
	"github.com/teambition/gear"
)

// Config ...
var Config ConfigTpl

var AppName = "auth-api"
var AppVersion = "0.1.0"
var BuildTime = "unknown"
var GitSHA1 = "unknown"

var once sync.Once

func init() {
	p := &Config
	readConfig(p)
	if err := p.Validate(); err != nil {
		panic(err)
	}
	p.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	p.GlobalCtx = gear.ContextWithSignal(context.Background())
}

type Logger struct {
	Level string `json:"level" toml:"level"`
}

type Server struct {
	Addr             string `json:"addr" toml:"addr"`
	GracefulShutdown uint   `json:"graceful_shutdown" toml:"graceful_shutdown"`
}

type Cookie struct {
	NamePrefix string `json:"name_prefix" toml:"name_prefix"`
	Domain     string `json:"domain" toml:"domain"`
	Secure     bool   `json:"secure" toml:"secure"`
	ExpiresIn  uint   `json:"expires_in" toml:"expires_in"`
}

type Userbase struct {
	Host string `json:"host" toml:"host"`
}

type Keys struct {
	CWTPub      string `json:"cwt_pub" toml:"cwt_pub"`
	Oauth2State string `json:"oauth2_state" toml:"oauth2_state"`
}

type Provider struct {
	ClientID     string   `json:"client_id" toml:"client_id"`
	ClientSecret string   `json:"client_secret" toml:"client_secret"`
	Scopes       []string `json:"scopes" toml:"scopes"`
}

// ConfigTpl ...
type ConfigTpl struct {
	Rand      *rand.Rand
	GlobalCtx context.Context
	Env       string              `json:"env" toml:"env"`
	Home      string              `json:"home" toml:"home"`
	Logger    Logger              `json:"log" toml:"log"`
	Server    Server              `json:"server" toml:"server"`
	Cookie    Cookie              `json:"cookie" toml:"cookie"`
	Userbase  Userbase            `json:"userbase" toml:"userbase"`
	Keys      Keys                `json:"keys" toml:"keys"`
	Providers map[string]Provider `json:"providers" toml:"providers"`
	COSEKeys  struct {
		CWTPub      key.Key
		Oauth2State key.Key
	}
}

func (c *ConfigTpl) Validate() error {
	var err error
	if c.COSEKeys.CWTPub, err = readKey(c.Keys.CWTPub); err != nil {
		return err
	}
	if c.COSEKeys.Oauth2State, err = readKey(c.Keys.Oauth2State); err != nil {
		return err
	}
	return nil
}

func readKey(filePath string) (k key.Key, err error) {
	var data []byte
	data, err = os.ReadFile(filePath)
	if err != nil {
		return
	}
	data, err = base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return
	}
	err = cbor.Unmarshal(data, &k)
	return
}

func readConfig(v interface{}, path ...string) {
	once.Do(func() {
		filePath, err := getConfigFilePath(path...)
		if err != nil {
			panic(err)
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			panic(err)
		}

		_, err = toml.Decode(string(data), v)
		if err != nil {
			panic(err)
		}
	})
}

func getConfigFilePath(path ...string) (string, error) {
	// 优先使用的环境变量
	filePath := os.Getenv("CONFIG_FILE_PATH")

	// 或使用指定的路径
	if filePath == "" && len(path) > 0 {
		filePath = path[0]
	}

	if filePath == "" {
		return "", fmt.Errorf("config file not specified")
	}

	return filePath, nil
}

package conf

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
	"github.com/teambition/gear"
	"github.com/yiwen-ai/auth-api/src/util"
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

type AuthURL struct {
	DefaultHost string   `json:"default_host" toml:"default_host"`
	DefaultPath string   `json:"default_path" toml:"default_path"`
	AllowHosts  []string `json:"allow_hosts" toml:"allow_hosts"`
	DefaultURL  url.URL
}

func (c *AuthURL) CheckNextUrl(nextUrl string) (url.URL, bool) {
	if u, err := url.Parse(nextUrl); err == nil {
		if u.Host == "" {
			u.Host = c.DefaultHost
			u.Scheme = "https"
		} else if !util.StringSliceHas(c.AllowHosts, u.Host) {
			return c.DefaultURL, false
		}

		return *u, true
	}

	return c.DefaultURL, false
}

func (c *AuthURL) GenNextUrl(u *url.URL, status int, xRequestId string) string {
	if u == nil {
		nextUrl := c.DefaultURL
		u = &nextUrl
	}

	if u.Host == "" {
		u.Host = c.DefaultHost
		u.Scheme = "https"
	}

	q := u.Query()
	q.Set("status", strconv.Itoa(status))
	if xRequestId != "" {
		q.Set("x-request-id", xRequestId)
	}
	u.RawQuery = q.Encode()
	return u.String()
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

type OSS struct {
	Bucket          string `json:"bucket" toml:"bucket"`
	Endpoint        string `json:"endpoint" toml:"endpoint"`
	AccessKeyId     string `json:"access_key_id" toml:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret" toml:"access_key_secret"`
	Prefix          string `json:"prefix" toml:"prefix"`
	UrlBase         string `json:"url_base" toml:"url_base"`
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
	AuthURL   AuthURL             `json:"auth_url" toml:"auth_url"`
	Userbase  Userbase            `json:"userbase" toml:"userbase"`
	Keys      Keys                `json:"keys" toml:"keys"`
	Providers map[string]Provider `json:"providers" toml:"providers"`
	OSS       OSS                 `json:"oss" toml:"oss"`
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

	c.AuthURL.DefaultURL = url.URL{
		Scheme: "https",
		Host:   c.AuthURL.DefaultHost,
		Path:   c.AuthURL.DefaultPath,
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

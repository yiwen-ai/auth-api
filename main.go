package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yiwen-ai/auth-api/src/api"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
)

var help = flag.Bool("help", false, "show help info")
var version = flag.Bool("version", false, "show version info")

func main() {
	flag.Parse()
	if *help || *version {
		data, _ := json.Marshal(api.GetVersion())
		fmt.Println(string(data))
		os.Exit(0)
	}

	app := api.NewApp()
	ctx := conf.Config.GlobalCtx
	host := "http://" + conf.Config.Server.Addr
	logging.Infof("auth-api start on %s", host)
	logging.Errf("auth-api closed %v", app.ListenWithContext(
		ctx, conf.Config.Server.Addr))
}

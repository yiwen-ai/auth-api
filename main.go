package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

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
	host := "http://" + conf.Config.Server.Addr
	logging.Infof("%s@%s start on %s", conf.AppName, conf.AppVersion, host)
	err := app.ListenWithContext(conf.Config.GlobalSignal, conf.Config.Server.Addr)
	logging.Warningf("%s@%s http server closed: %v", conf.AppName, conf.AppVersion, err)

	ctx := conf.Config.GlobalShutdown
	for {
		if conf.Config.JobsIdle() {
			logging.Infof("%s@%s shutdown: OK", conf.AppName, conf.AppVersion)
			return
		}

		select {
		case <-ctx.Done():
			logging.Errf("%s@%s shutdown: %v", conf.AppName, conf.AppVersion, ctx.Err())
			return
		case <-time.After(time.Second):
		}
	}
}

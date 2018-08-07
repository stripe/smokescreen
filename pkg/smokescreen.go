package pkg

import internal "github.com/stripe/smokescreen/internal/pkg"
import config "github.com/stripe/smokescreen/pkg/config"

func StartServer(conf *config.SmokescreenConfig) {
	internal.StartWithConfig(conf)
}

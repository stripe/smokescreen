package smoker

import (
	"log"
	"net/http"
	"os"
)

type HealthcheckMiddleware struct {
	App             http.Handler
	MaintenanceFile string
}

func (h HealthcheckMiddleware) analyzeError(err error) (bool, error) {
	if os.IsNotExist(err) {
		// Non-existent file is a warning, but we're alive
		log.Printf(
			"WARN: maintenance file does not exist: path=%#v\n",
			h.MaintenanceFile)
		return true, nil
	} else if os.IsPermission(err) {
		// Maintenance mode!
		return false, nil
	}

	return false, err
}

func (h HealthcheckMiddleware) healthy() (bool, error) {
	fi, err := os.Stat(h.MaintenanceFile)
	if err != nil {
		return h.analyzeError(err)
	}

	perms := fi.Mode().Perm()
	if perms == 0644 {
		return true, nil
	} else if perms == 0000 {
		// Maintenance mode!
		return false, nil
	} else {
		log.Printf("WARN: unexpected perms on maintenance file: "+
			"path=%#v perms=%#v\n",
			h.MaintenanceFile, perms)
		return true, nil
	}
}

func (h HealthcheckMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthcheck" {
		healthy, err := h.healthy()
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		} else if healthy {
			w.WriteHeader(200)
			w.Write([]byte("Service is up.\n"))
		} else {
			w.WriteHeader(404)
			w.Write([]byte("Host is in maintenance mode.\n"))
		}
	} else {
		h.App.ServeHTTP(w, r)
	}
}

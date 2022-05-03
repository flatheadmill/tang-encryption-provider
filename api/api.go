package api

import (
	"github.com/pkg/errors"
	"net/http"
)

type Healther interface {
	Health() error
}

type ComponentHealth interface {
	Healther
	Name() string
}

type healthAPI struct {
	l          logger
	components []ComponentHealth
	// add logger
}

type logger interface {
	Err(error) bool
}

func NewHealthAPI(l logger, components ...ComponentHealth) healthAPI {
	return healthAPI{l: l, components: components}
}

func (api *healthAPI) Health(w http.ResponseWriter, r *http.Request) {
	errs := []error{}

	for _, component := range api.components {
		errs = append(errs, errors.Wrapf(component.Health(), "failed health check for component %q", component.Name()))
	}

	respBody := []byte("ok")
	if logErrs(api.l, errs) {
		w.WriteHeader(http.StatusInternalServerError)
		respBody = []byte("error")
	}
	_, err := w.Write(respBody)
	if err != nil {
		api.l.Err(errors.Wrap(err, "failed to write http response"))
	}
}

func logErrs(l logger, errs []error) bool {
	loggedErr := false
	for _, err := range errs {
		if l.Err(err) {
			loggedErr = true
		}
	}
	return loggedErr
}

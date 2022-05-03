package api

import (
	"fmt"
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
	components []ComponentHealth
	// add logger
}

func NewHealthAPI(components ...ComponentHealth) healthAPI {
	return healthAPI{components: components}
}

func (api *healthAPI) Health(w http.ResponseWriter, r *http.Request) {
	errs := []error{}

	for _, component := range api.components {
		errs = append(errs, errors.Wrapf(component.Health(), "failed health check for component %q", component.Name()))
	}

	errStrings := errsToStrings(errs)
	respBody := []byte("ok")
	if len(errStrings) > 0 {
		w.WriteHeader(http.StatusInternalServerError)
		//respBody = []byte(strings.Join(errStrings, " - "))
		respBody = []byte("error")
	}
	_, err := w.Write(respBody)
	if err != nil {
		fmt.Printf("%+v\n", errors.Wrap(err, "failed to write http response"))
	}
}

func errsToStrings(errs []error) []string {
	errStrs := []string{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		errStrs = append(errStrs, err.Error())
	}
	return errStrs
}

package api

import (
	"encoding/json"
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
	if len(errStrings) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respBody, err := json.Marshal(map[string]interface{}{"errors": errStrings})
		if err != nil {
			respBody = []byte(fmt.Sprintf("%+v", errors.Wrap(err, "failed to marshal errors to json")))

		}
		_, err = w.Write(respBody)
		if err != nil {
			fmt.Printf("%+v\n", errors.Wrap(err, "failed to write http response"))
		}

		return
	}
	w.WriteHeader(http.StatusOK)
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

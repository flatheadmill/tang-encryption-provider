// vim: colorcolumn=80
package clevis

import (
    "os"
    "fmt"
    "io/ioutil"
    "net/http"
)

type Advertisement struct {
    jwe string
}

const thp = "o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY"
const url = 'http://tang:8080'

func Initialize () (error) {
    response, err := http.Get("http://tang:8080/adv")
    if err != nil {
        return err
    }
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return err
    }
    fmt.Fprintf(os.Stderr, "hello %+v\n",  body)
    return nil
}

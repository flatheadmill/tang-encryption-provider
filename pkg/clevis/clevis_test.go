package clevis

import (
    "fmt"
    "os"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestAdvertisment (t *testing.T) {
    assert := assert.New(t)
    _ = Advertisement{}
    err := Initialize()
    if err != nil {
        fmt.Fprintf(os.Stderr, "number of foo: %v", err)
    }
    assert.Nil(err, "error")
    assert.Equal(1, 1, "one equals one")
}

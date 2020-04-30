package authz

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func pipeRequestBody(r *http.Request, w io.Writer) error {
	if r.Body == nil {
		return nil
	}

	var body bytes.Buffer
	defer r.Body.Close()
	n, err := io.Copy(w, io.TeeReader(r.Body, &body))
	if err != nil {
		return err
	}

	log.Printf("Bytes written: %d", n)

	r.Body = ioutil.NopCloser(&body)
	return err
}

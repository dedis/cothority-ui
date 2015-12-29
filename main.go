package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/crypto/abstract"
	//"html/template"
	"log"
	"net/http"
	"net/http/fcgi"
)

// XXX make this a commandline flag
var appAddr string

/****** Copy & Paste from stamp.go ******/

// Default config file
// if you have network access: use config.toml from the latest release (epfl cothority)
const defaultConfigFile = "config.toml"

// if you currently do not have internet access, you can generate a new config.toml
// using the script app/conode/run_locally.sh and copy it to the top-level dir
// of this project:
//const defaultConfigFile = "local.toml"

// Our crypto-suite used in the program
var suite abstract.Suite

// the configuration file of the cothority tree used
var conf *app.ConfigConode

// The public aggregate X0
var public_X0 abstract.Point

/******END: Copy & Paste from stamp.go ******/

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	appAddr = os.Getenv("APP_ADDR") // e.g. "0.0.0.0:8080" or ""

	conf = new(app.ConfigConode)
	if err := app.ReadTomlConfig(conf, defaultConfigFile); err != nil {
		fmt.Printf("Couldn't read configuration file: %v", err)
		os.Exit(1)
	}

	suite = app.GetSuite(conf.Suite)
	pub, _ := base64.StdEncoding.DecodeString(conf.AggPubKey)
	suite.Read(bytes.NewReader(pub), &public_X0)
}

func sign(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.Method == "GET" {
		http.ServeFile(w, r, "static/sign.html")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
		jsonType := "application/json"
		if strings.Index(r.Header.Get("Accept"), jsonType) != -1 {
			w.Header().Set("Content-Type", jsonType)
		}

		r.ParseMultipartForm(32 << 20)
		file, handler, err := r.FormFile("file-sign")
		if err != nil {
			b, _ := MarshalErrorJSON(err)
			fmt.Fprintln(w, string(b))
		}
		defer file.Close()
		sig, err := stampFile(file, handler.Filename)
		if err != nil {
			b, _ := MarshalErrorJSON(err)
			fmt.Fprintln(w, string(b))
		} else {
			var err error
			var b []byte
			var data *SignatureData
			data, err = NewSignatureData(sig, handler.Filename)
			if err != nil {
				b, _ = MarshalErrorJSON(err)
			}
			b, err = json.Marshal(struct {
				Data SignatureData `json:"data"`
			}{*data})
			if err != nil {
				b, _ = MarshalErrorJSON(err)
			}
			fmt.Fprintln(w, string(b))
		}
	}
}

func verify(w http.ResponseWriter, r *http.Request) {
	fmt.Println("method:", r.Method) //get request method
	r.ParseForm()
	if r.Method == "GET" {
		http.ServeFile(w, r, "static/verify.html")
	} else {
		r.ParseForm()
		fmt.Fprintln(w, "{error: 'Not implemented'}")
	}
}
func landing(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/landing.html")
}

func main() {
	// fcgi: https://github.com/bsingr/golang-apache-fastcgi/blob/master/examples/vanilla/hello_world.go
	http.HandleFunc("/start", landing)
	http.HandleFunc("/sign", sign) // setting router rule
	http.HandleFunc("/verify", verify)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	var err error
	if appAddr != "" { // Run as a local web server
		err = http.ListenAndServe(appAddr, nil) // setting listening port
	} else { // run over FCGI via standard I/O
		err = fcgi.Serve(nil, nil)
	}
	if err != nil {
		log.Fatal("Could not serve: ", err)
	}
}

// Takes a 'filestream' to hash and being stamped at the 'server'. The output of the
// signing will be written to 'file'.sig
func stampFile(filestream io.Reader, origFilename string) (*conode.StampSignature, error) {
	// Create the hash of the file and send it over the net
	myHash := hashFile(filestream)

	// XXX: why do we need to specify the config here again (compare stamp.go) ???
	stamper, err := conode.NewStamp(defaultConfigFile)
	if err != nil {
		log.Println("Couldn't setup stamper:", err)
		return nil, err
	}

	// empty servers string: randomly pick server from config
	tsm, err := stamper.GetStamp(myHash, "")
	if err != nil {
		dbg.Print("Stamper didn't succeed:", err)
		return nil, err
	}

	return tsm.Srep, nil // no error
}

// modified version of hashFile from stamp.go to handle io.Reader instead of
// (filename string); in other words: it does not write to the filesystem
func hashFile(file io.Reader) []byte {
	hash := suite.Hash()
	buflen := 1024 * 1024
	buf := make([]byte, buflen)
	read := buflen
	for read == buflen {
		var err error
		read, err = file.Read(buf)
		if err != nil && err != io.EOF {
			dbg.Fatal("Error while reading bytes")
		}
		hash.Write(buf)
	}
	return hash.Sum(nil)
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/conode"
	"github.com/dedis/cothority/lib/dbg"
	"github.com/dedis/crypto/abstract"
	//"html/template"
	"log"
	"net/http"
)

var listenPort = ":9090"

/****** Copy & Paste from stamp.go ******/

// Default config file
// if you have network access: use config.toml from the latest release (epfl cothority)
const defaultConfigFile = "config.toml"

// if you currently do not have internet access, you can generate a new config.toml
// using the script app/conode/run_locally.sh and copy it to the top-level dir
// of this project:
//const defaultConfigFile = "local.toml"

// extension given to a signature file
const sigExtension = ".sig"

// Our crypto-suite used in the program
var suite abstract.Suite

// the configuration file of the cothority tree used
var conf *app.ConfigConode

// The public aggregate X0
var public_X0 abstract.Point

/******END: Copy & Paste from stamp.go ******/

func init() {
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
	r.ParseForm() //Parse url parameters passed, then parse the response packet for the POST body (request body)
	// attention: If you do not call ParseForm method, the following data can not be obtained form
	if r.Method == "GET" {
		http.ServeFile(w, r, "static/sign.html")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
		jsonType := "application/json"
		if strings.Index(r.Header.Get("Accept"), jsonType) != -1 {
			w.Header().Set("Content-Type", jsonType)
		}

		// TODO return JSON (modify post in JS  to use ajax first)
		r.ParseMultipartForm(32 << 20)
		file, handler, err := r.FormFile("file-sign")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		//fmt.Fprintf(w, "%v", handler.Header)
		var sig *conode.StampSignature
		sig, err = stampFile(file, handler.Filename)
		if err != nil {
			b, _ := json.Marshal(struct {
				Error_ string `json:"error"`
			}{err.Error()})
			fmt.Fprint(w, string(b))
		} else {
			b, _ := json.Marshal(struct {
				// TODO nice short preview of the signature & make it downloadable for the user
				Signature conode.StampSignature `json:"data"`
			}{*sig})

			fmt.Fprintln(w, string(b))
		}

		// f, err := os.OpenFile("./test/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		// defer f.Close()
		// io.Copy(f, file)

		// fmt.Println(r.Form) // print information on server side.
		// fmt.Println("path", r.URL.Path)
		// fmt.Println("scheme", r.URL.Scheme)
		// fmt.Println(r.Form["form_name"])
		// for k, v := range r.Form {
		// 	fmt.Println("key:", k)
		// 	fmt.Println("val:", strings.Join(v, ""))
		// }
		// fmt.Fprintf(w, "TODO: call conode to generate signature") // write data to response
	}
}

func verify(w http.ResponseWriter, r *http.Request) {
	fmt.Println("method:", r.Method) //get request method
	r.ParseForm()
	if r.Method == "GET" {
		//
	} else {
		r.ParseForm()
		// logic part of log in
		fmt.Println("username:", r.Form["username"])
	}
}
func landing(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/landing.html")
}

func main() {
	http.HandleFunc("/start", landing)
	http.HandleFunc("/sign", sign) // setting router rule
	http.HandleFunc("/verify", verify)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	err := http.ListenAndServe(listenPort, nil) // setting listening port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
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
// (filename string); in other words does not write to filesystem
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

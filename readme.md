**⚠️ This app uses an older version of cothority and is no longer maintained.**

## Usage

You need a valid config.toml (see latest [release](https://github.com/dedis/cothority/releases/latest)) or create one by using [run_locally.sh](https://github.com/dedis/cothority/blob/development/app/conode/run_locally.sh) if you are offline.

If you have a valid config you can run the server by
```
$ go get -d github.com/dedis/cothority-ui
$ cd $GOPATH/dedis/cothority-ui
$ go get -u ./...
$ go build ./...
$ ./cothority-ui
```
and visit [http://localhost:9090/start](http://localhost:9090/start) in your browser.

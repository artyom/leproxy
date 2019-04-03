package main

import (
	"os"
	"path"
)

func cachePath() string {
	return path.Join(os.Getenv("PROGRAMDATA"), "leproxy", "letsencrypt")
}

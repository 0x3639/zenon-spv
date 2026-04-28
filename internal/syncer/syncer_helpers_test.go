package syncer

import "encoding/base64"

// base64StdLib is package-level so syncer_test.go's stdlibBase64 can
// reach it without polluting the production import set.
var base64StdLib = base64.StdEncoding

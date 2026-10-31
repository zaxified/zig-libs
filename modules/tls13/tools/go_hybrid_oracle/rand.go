// SPDX-License-Identifier: MIT

package main

import (
	crand "crypto/rand"
	"io"
)

func rand() io.Reader { return crand.Reader }

package fingerprintverifier

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Warner is a function that gets called when the fingerprint verifier wants
// to show a warning. By default it prints the warning to stderr. This is a
// variable so you can replace it if you want to suppress or handle the
// warnings. Here is an example of a string that would get passed to this
// function:
//   not validating host key nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 for github.com
var Warner = func(msg string) {
	fmt.Fprintln(os.Stderr, "WARNING: "+msg)
}

// New returns a function matching the ssh.HostKeyCallback type that can be
// passed as the HostKeyCallback in the ssh ClientConfig. The fingerprint
// may be in the format
//   MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48
//   16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48
//   MD5:16:27:AC:A5:76:28:2D:36:63:1B:56:4D:EB:DF:A6:48
//   16:27:AC:A5:76:28:2D:36:63:1B:56:4D:EB:DF:A6:48
//   SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
//   nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
// To get a host's fingerprint run this (replace github.com with your host):
//   ssh-keyscan github.com | ssh-keygen -lf -
// If an empty string is given this will print a warning using Warner()
// containing the SHA256 key.
func New(fingerprint string) ssh.HostKeyCallback {
	return func(hostname string, ip net.Addr, key ssh.PublicKey) error {
		// calculate the correct fingerprint
		md5 := fingerprintMD5(key)
		sha256 := fingerprintSHA256(key)

		// if fingerprint is empty accept it with a warning
		if fingerprint == "" {
			// this is the name we will show to the user to help them
			// identify the device. we prefer hostname, but will fall back
			// to IP
			var deviceString string
			if len(hostname) > 0 {
				deviceString = hostname
			} else {
				deviceString = ip.String()
			}

			// show the user a warning with the sha256 fingerprint.
			Warner("not validating host key " + sha256 + " for " + deviceString)
			return nil
		}

		// trim prefix from the provided fingerprint if it has one
		fingerprint = strings.TrimPrefix(fingerprint, "MD5:")
		fingerprint = strings.TrimPrefix(fingerprint, "SHA256:")

		// check if the fingerprints match (md5 is case insensitive)
		if strings.EqualFold(fingerprint, md5) || fingerprint == sha256 {
			return nil
		} else {
			return fmt.Errorf("Fingerprint did not match %s", sha256)
		}
	}
}

// hexadecimal md5 hash grouped by 2 characters separated by colons
func fingerprintMD5(key ssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	out := ""
	for i := 0; i < 16; i++ {
		if i > 0 {
			out += ":"
		}
		// don't forget the leading zeroes
		out += fmt.Sprintf("%02x", hash[i])
	}
	return out
}

// base64 sha256 hash with the trailing equal sign removed
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return strings.TrimRight(b64hash, "=")
}

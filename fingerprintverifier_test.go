package fingerprintverifier_test

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/9072997/fingerprintverifier"
	gliderlabsssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// this is a helper to make connections to the local test server and capture
// output
func doSSHConnection(fingerprint string) (errMsg, warnMsg string) {
	// make a function to catch warning messages
	warnMsg = "Warner function not called"
	fingerprintverifier.Warner = func(msg string) {
		warnMsg = msg
	}

	sshConfig := &ssh.ClientConfig{
		Timeout:         time.Second * 10,
		User:            "testuser",
		Auth:            nil,
		HostKeyCallback: fingerprintverifier.New(fingerprint),
	}

	sshConn, err := ssh.Dial("tcp", "localhost:1022", sshConfig)
	if err != nil {
		return err.Error(), warnMsg
	}
	defer sshConn.Close()

	return "no error", warnMsg
}

// start up a test ssh server on port 1022
func init() {
	// set up host key
	// the fingerprints for this key are
	// MD5:a7:a2:0a:62:50:17:20:8d:a6:fa:fa:a1:cc:11:bf:a9
	// SHA256:giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc
	key := gliderlabsssh.HostKeyPEM([]byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA0LfYsxlMYdAzNNMrQLE+/STEs57AhfGJwWytN8CeWSsnp8f0/Ye7
knQ2+xuWGYKzerDJ+LMWveUJDLBQ6cW7i+W52PvKS9d3lGmoFkKhz0HOHULWeOvKOK9rbu
vnpHUhnzJ4OXirp5sg657oF7Z0SvmuPqZThTzay8AWOW924A0AAAIIW8BteFvAbXgAAAAH
c3NoLXJzYQAAAIEA0LfYsxlMYdAzNNMrQLE+/STEs57AhfGJwWytN8CeWSsnp8f0/Ye7kn
Q2+xuWGYKzerDJ+LMWveUJDLBQ6cW7i+W52PvKS9d3lGmoFkKhz0HOHULWeOvKOK9rbuvn
pHUhnzJ4OXirp5sg657oF7Z0SvmuPqZThTzay8AWOW924A0AAAADAQABAAAAgG9D4sCvVt
m5/OJHRIKLOrIGfNnoYmfFOJOllL3o8EFG0TAPV5okVqkfTQQWU7ErzPQ19KWhCxmWVHmw
MKI+59gX7291KLPwsrGBbA6R2y2esKLhdAXP7w4X7AJ3R4H4OUkZR07AaU4bFtdAZAzEZ1
cNZdfAcRFfFAdx8V97RkZ9AAAAQQCpZe///S5RobgEpWFmd4rEie/CUtAs6RoMnccqutbt
CQC4mLMMWcybVfkuV5KJ7ExkmfSfnGS8k81nKCjQ5HliAAAAQQD8Jf2e9JaYKj5cbAXLcY
+ImipIbLkmkPefJqcbRDqWLGqmRFMCmBAtMqYjfuOsGaWev3YN9xuUH7AJRlf3GnEvAAAA
QQDT6AZTm7t3If/9WhPlPd4BVSzQM0CymSJLr7jhJbdahskBaPkRWGZpvWUIUOs7OGEaCL
jEBtgGQ1+cVtXHMRuDAAAAD2pwZW5uQFRFQ0hKUEVOTgECAw==
-----END OPENSSH PRIVATE KEY-----`,
	))

	gliderlabsssh.Handle(func(s gliderlabsssh.Session) {
		io.WriteString(s, "Hello world\n")
	})

	go func() {
		log.Fatal(gliderlabsssh.ListenAndServe(":1022", nil, key))
	}()
}

func TestAll(t *testing.T) {
	testCases := [][3]string{
		// key, expected error message, expected warning message
		[3]string{"SHA256:giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "no error", "Warner function not called"},
		[3]string{"giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "no error", "Warner function not called"},
		[3]string{"MD5:a7:a2:0a:62:50:17:20:8d:a6:fa:fa:a1:cc:11:bf:a9", "no error", "Warner function not called"},
		[3]string{"a7:a2:0a:62:50:17:20:8d:a6:fa:fa:a1:cc:11:bf:a9", "no error", "Warner function not called"},
		// md5 is base16 encoded, so we don't need to care about case
		[3]string{"MD5:A7:A2:0A:62:50:17:20:8D:A6:FA:FA:A1:CC:11:BF:A9", "no error", "Warner function not called"},
		[3]string{"A7:A2:0A:62:50:17:20:8D:A6:FA:FA:A1:CC:11:BF:A9", "no error", "Warner function not called"},
		// several incorrect keys formatted correctly and a random string
		[3]string{"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"MD5:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"foo", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		// SHA256 keys are case sensitive, so wrong case should fail
		[3]string{"SHA256:GIDWJD2E7GASEUCG7NIN2TKNYIWJF+FRLRV52GVBDUC", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"SHA256:gidwjd2e7gaseucg7nin2tknyiwjf+frlrv52gvbduc", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"GIDWJD2E7GASEUCG7NIN2TKNYIWJF+FRLRV52GVBDUC", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		[3]string{"gidwjd2e7gaseucg7nin2tknyiwjf+frlrv52gvbduc", "ssh: handshake failed: Fingerprint did not match giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc", "Warner function not called"},
		// empty string should generate a warning
		[3]string{"", "no error", "not validating host key giDwjd2E7GAsEuCG7nin2TKNyIWJf+FrLrV52Gvbduc for localhost:1022"},
	}

	for testNum, testCase := range testCases {
		errMsg, warnMsg := doSSHConnection(testCase[0])
		if errMsg != testCase[1] || warnMsg != testCase[2] {
			t.Errorf(`Got error "%s" and warning "%s" for test case %d`, errMsg, warnMsg, testNum)
		} else {
			t.Logf(`Case %d passed`, testNum)
		}
	}
}

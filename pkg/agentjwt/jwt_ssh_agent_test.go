package agentjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var tmpDir string
var port int
var trustedKeys map[string]string

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "dbt-server")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir
	fmt.Printf("Temp dir: %s\n", tmpDir)

	freePort, err := freeport.GetFreePort()
	if err != nil {
		log.Printf("Error getting a free port: %s", err)
		os.Exit(1)
	}

	port = freePort

	trustedKeys = make(map[string]string)

	// Set up the repo server
	repo := TestServer{
		Address:    "127.0.0.1",
		Port:       port,
		PubkeyFunc: pubkeyForUsername,
	}

	// Run it in the background
	go repo.RunTestServer()
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
}

func pubkeyForUsername(username string) (pubkey string, err error) {
	pubkey = trustedKeys[username]
	return pubkey, err
}

func generateSSHKey(privateKeyPath string, blockSize int) (err error) {
	pubKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if blockSize == 0 {
		blockSize = 2048
	}

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, blockSize)
	if err != nil {
		err = errors.Wrapf(err, "failed to generate key")
		return err
	}

	err = privateKey.Validate()
	if err != nil {
		err = errors.Wrapf(err, "generated key failed to validate")
		return err
	}

	// generate public key
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		err = errors.Wrapf(err, "failed to generate public key")
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateDER,
	}

	privatePEM := pem.EncodeToMemory(&privBlock)

	err = ioutil.WriteFile(privateKeyPath, privatePEM, 0600)
	if err != nil {
		err = errors.Wrapf(err, "failed to write private key to %s", privateKeyPath)
		return err
	}

	err = ioutil.WriteFile(pubKeyPath, pubKeyBytes, 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed to write public key fo %s", pubKeyPath)
		return err
	}

	return err
}

func TestPubkeyAuth(t *testing.T) {
	// generate a 'good' key
	goodPrivatePath := fmt.Sprintf("%s/id_rsa_good", tmpDir)
	goodPublicPath := fmt.Sprintf("%s/id_rsa_good.pub", tmpDir)

	err := generateSSHKey(goodPrivatePath, 2048)
	if err != nil {
		fmt.Printf("Error generating good key: %s\n", err)
		t.Fail()
	}

	// generate a 'bad' key
	badPrivatePath := fmt.Sprintf("%s/id_rsa_bad", tmpDir)
	badPublicPath := fmt.Sprintf("%s/id_rsa_bad.pub", tmpDir)

	err = generateSSHKey(badPrivatePath, 2048)
	if err != nil {
		fmt.Printf("Error generating bad key: %s\n", err)
		t.Fail()
	}

	// spin up an agent
	sshAgentBinary, err := exec.LookPath("ssh-agent")
	if err != nil {
		fmt.Printf("ssh-agent not found in path: %s", err)
		t.Fail()
	}

	out, err := exec.Command(sshAgentBinary).Output()
	if err != nil {
		fmt.Printf("Failed starting ssh-agent: %s", err)
		t.Fail()
	}

	var agentPid string
	var agentSock string
	pidrx := regexp.MustCompile(`SSH_AGENT_PID=`)
	sockrx := regexp.MustCompile(`SSH_AUTH_SOCK=`)
	parts := strings.Split(string(out), ";")

	for _, p := range parts {
		if pidrx.MatchString(p) {
			parts := strings.Split(p, "=")
			agentPid = parts[1]
		} else if sockrx.MatchString(p) {
			parts := strings.Split(p, "=")
			agentSock = parts[1]
		}
	}

	// load the 'good' key into it
	sshAdd, err := exec.LookPath("ssh-add")
	if err != nil {
		fmt.Printf("ssh-add not found in path: %s", err)
		t.Fail()
	}

	cmd := exec.Command(sshAdd, goodPrivatePath)
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", agentPid),
		fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSock),
	}
	err = cmd.Run()
	if err != nil {
		fmt.Printf("failed to load private key into ssh agent: %s\n", err)
		t.Fail()
	}

	// load the 'bad' key into it too, else we cannot test
	cmd = exec.Command(sshAdd, badPrivatePath)
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", agentPid),
		fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSock),
	}
	err = cmd.Run()
	if err != nil {
		fmt.Printf("failed to load private key into ssh agent: %s\n", err)
		t.Fail()
	}

	goodPubkeyBytes, err := ioutil.ReadFile(goodPublicPath)
	if err != nil {
		fmt.Printf("failed to read good public key file %s: %s\n", goodPublicPath, err)
		t.Fail()
	}

	goodPublicKey := string(goodPubkeyBytes)

	// load 'good' public key into the test keystore
	username := "test-user"
	trustedKeys[username] = goodPublicKey

	badPubkeyBytes, err := ioutil.ReadFile(badPublicPath)
	if err != nil {
		fmt.Printf("failed to read good public key file %s: %s\n", goodPublicPath, err)
		t.Fail()
	}

	badPublicKey := string(badPubkeyBytes)

	assert.NotEqual(t, goodPublicKey, badPublicKey, "Good and bad keys match- they should not.")

	// override SSH_AUTH_SOCK to point at the test agent
	_ = os.Setenv("SSH_AGENT_PID", agentPid)
	_ = os.Setenv("SSH_AUTH_SOCK", agentSock)

	// Test Shtuff
	inputs := []struct {
		name string
		key  string
		out  error
	}{
		{
			"good key",
			goodPublicKey,
			nil,
		},
		{
			"bad key",
			badPublicKey,
			errors.New("Bad Response: 400"), // This is a kludge.  Fix it.
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			address := "http://127.0.0.1"
			path := ""
			url := fmt.Sprintf("%s:%d/%s", address, port, path)

			fmt.Printf("Testing %s\n", tc.name)

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				err = errors.Wrapf(err, "failed creating request to %s", url)
				fmt.Printf("Error: %s", err)
				t.Fail()
			}

			token, err := SignedJwtToken(username, tc.key)
			if err != nil {
				err = errors.Wrap(err, "failed to create signed token")
				fmt.Printf("Error: %s", err)
				t.Fail()
			}

			req.Header.Set("Token", token)

			// Make the request
			client := &http.Client{}

			resp, err := client.Do(req)
			if err != nil {
				err = errors.Wrap(err, "failed making http request")
				fmt.Printf("Error: %s", err)
				t.Fail()
			}

			if resp.StatusCode != 200 {
				err = errors.New(fmt.Sprintf("Bad Response: %d", resp.StatusCode))
			}

			if tc.out == nil {
				assert.Equal(t, tc.out, err, "Error where there should not be")
			} else {
				if err == nil {
					t.Fail()
				} else {
					assert.Equal(t, tc.out.Error(), err.Error(), "Unexpected Error")
				}
			}
		})
	}

	// Teardown the agent ssh-agent -k SSH_AGENT_PID
	cmd = exec.Command(sshAgentBinary, "-k")
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", agentPid),
	}

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed killing ssh-agent: %s", err)
		t.Fail()
	}
}

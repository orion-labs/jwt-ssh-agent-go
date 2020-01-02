# jwt-ssh-agent-go

[![CircleCI](https://circleci.com/gh/OnBeep/jwt-ssh-agent-go.svg?style=svg)](https://circleci.com/gh/OnBeep/jwt-ssh-agent-go)

Create and JWT Tokens with private keys from a running ssh-agent.  Parse and validate them with SSH public keys.

## Description

The JWT spec provides for token signing via both symmetric and asymmetric cryptography. One very common usage of asymmetric crypto lies in the familiar SSH public and private keys.

In order to avoid the twin evils of unencrypted keys and constantly typing in one's passphrase, the venerable `ssh-agent` can be used to hold the SSH private key in escrow and sign messages with it when asked nicely.

The JWT spec and `ssh-agent` have a single hashing algorithm in common.  JWT calls it "RS256".  `ssh-agent` calls it RSA SHA 256.  Names aside, they use the SHA 256 algorithm to hash messages that are later signed by the user's private key and verified by the remote server to establish identity.

While the hashing algorithms are compatible, the normal use cases for each system are slightly different and therefore required some extra work to connect the two.  

The general design of JWT libraries expect the unencrypted private key to be available for signing.  Keys held by the agent are off limits until now.  With this library, or the techniques demonstrated herein you can create a perfectly valid JWT signed by a private key held by your local `ssh-agent`.

This use case presupposes that the remote server has access to a trusted list of Subjects and Public keys.  The library is designed to take a callback that will produce a public key for a given subject.

The callback could fetch public keys from a local file, a directory server, or anything you can conceive of in a similar fashion to the AuthorizedKeysCommand from [man(5) sshd_config](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand).

Passwordless auth from CLI utilities to a JWT protected web server or service is definitely not a common use case for JWT, but it can be occasionally just what the doctor orders.

## Usage

To use this library in it's current state, you need to know the name of a subject to authenticate, a public key string corresponding to that subject, and of course, the subject's private key loaded into a running ssh-agent. 

How you get them is up to you, but at it's crudest:

    // Get a user objet
    userObj, err := user.Current()
    if err != nil {
      log.Fatalf("Failed to get current user: %s", err)
    }
    
    // Read the default public key
    pubkeyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa.pub", userObj.HomeDir))
    if err != nil {
      log.Fatalf("Failed to read public key file: %s", err)
    }
    
    subject := userObj.Username
    publicKey := string(pubkeyBytes)
    
    // Make a signed token
    token, err := SignedJwtToken(username, tc.key)
    if err != nil {
        err = errors.Wrap(err, "failed to create signed token")
        fmt.Printf("Error: %s", err)
        t.Fail()
    }
    
    // create a request
    url := "http://test.org"

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        err = errors.Wrapf(err, "failed creating request to %s", url)
        fmt.Printf("Error: %s", err)
        t.Fail()
    }

    // Set the token on the request
    req.Header.Set("Token", token)

    // Make the request
    client := &http.Client{}

    resp, err := client.Do(req)
    if err != nil {
        err = errors.Wrap(err, "failed making http request")
        log.Fatal(err)
    }

    if resp.StatusCode != 200 {
        err = errors.New(fmt.Sprintf("Bad Response: %d", resp.StatusCode))
        log.Fatal(err)
    }
    
This of course presupposes the remote server is prepared to handle JWT's of this type.  Most will not be able to handle it off the shelf.  

The TestServer struct in this package demonstrates a minimal example of an HTTP server that can be expanded upon to provide this functionality.

## Limitations

This library in its current form only works for RSA keys.  To support the full range of keys creatable via `ssh-keygen` more work will need to be done.  Stay tuned.
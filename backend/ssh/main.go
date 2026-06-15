package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"regexp"

	"github.com/xmit-co/ident.me/backend/internal/metrics"
)

var (
	removePort = regexp.MustCompile(`^\[?([^\]]*)\]?:\d*$`)
)

var tracker = metrics.NewTracker(nil)

func main() {
	sshConfig := ssh.ServerConfig{
		NoClientAuth: true,
	}
	addKey(&sshConfig, "/etc/ssh/ssh_host_ecdsa_key")
	addKey(&sshConfig, "/etc/ssh/ssh_host_ed25519_key")
	addKey(&sshConfig, "/etc/ssh/ssh_host_rsa_key")

	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		log.Fatalf("Failed to listen on port 22 (%s)", err)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept (%s)", err)
			continue
		}

		go func() {
			sshConn, sshChannels, channelReqs, err := ssh.NewServerConn(tcpConn, &sshConfig)
			if err != nil {
				log.Printf("Failed to handshake (%s)", err)
				return
			}
			go ssh.DiscardRequests(channelReqs)

			for c := range sshChannels {
				channel := c
				go func() {
					if t := channel.ChannelType(); t != "session" {
						log.Printf("Rejecting channel type %s", t)
						err := channel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
						if err != nil {
							log.Printf("Failed to reject channel type %s (%s)", t, err)
						}
						return
					}

					channel, reqs, err := channel.Accept()
					if err != nil {
						log.Printf("Could not accept channel (%s)", err)
						return
					}

					go func() {
						for req := range reqs {
							switch req.Type {
							case "shell", "exec":
								go handleRequest(req, sshConn, channel)
								err = req.Reply(true, nil)
								if err != nil {
									log.Printf("Could not reply (%s)", err)
								}
							default:
								err = req.Reply(true, nil)
								if err != nil {
									log.Printf("Could not reply (%s)", err)
								}
							}
						}
					}()
				}()
			}
		}()
	}
}

func addKey(sshConfig *ssh.ServerConfig, path string) {
	privateBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to load private key (%s): %s", path, err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key (%s): %s", path, err)
	}

	sshConfig.AddHostKey(private)
}

func handleRequest(req *ssh.Request, sshConn *ssh.ServerConn, channel ssh.Channel) {
	cmd := string(req.Payload)
	response := ""
	switch cmd {
	case "":
		response = removePort.ReplaceAllString(sshConn.RemoteAddr().String(), "$1")
	}
	if response != "" {
		if err := tracker.RecordRequest(context.Background(), response, string(sshConn.ClientVersion())); err != nil {
			log.Printf("Failed to record SSH hit for %v (%v)", response, err)
		}
	}
	if _, err := channel.Write([]byte(response)); err != nil {
		log.Printf("Could not write answer (%s)", err)
	}
	log.Printf("Resolved %v", response)
	_, err := channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	if err != nil {
		log.Printf("Could not return exit status (%s)", err)
	}
	if err := channel.Close(); err != nil {
		log.Printf("Could not close (%s)", err)
	}
}

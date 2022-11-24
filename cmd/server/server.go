package main

import (
	"flag"
	"log"
	"os"
	"strconv"

	"codeberg.org/peterzam/socks5"
)

var (
	user = flag.String("user", "", "proxy username")
	pass = flag.String("pass", "", "proxy password")
	inf  = flag.String("inf", "lo", "proxy out interface")
	port = flag.Int("port", 1080, "proxy port")
)

func main() {
	flag.Parse()
	socsk5conf := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
		BindIP: socks5.GetInterfaceIpv4Addr(*inf),
	}

	if *user+*pass != "" {
		creds := socks5.StaticCredentials{
			*user: *pass,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		socsk5conf.AuthMethods = []socks5.Authenticator{cator}
	}

	server, err := socks5.New(socsk5conf)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Start listening proxy service on port %s\n", strconv.Itoa(*port))
	log.Println("Route from ", socsk5conf.BindIP)
	if err := server.ListenAndServe("tcp", ":"+strconv.Itoa(*port)); err != nil {
		log.Fatal(err)
	}

}

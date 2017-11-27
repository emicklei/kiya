package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/atotto/clipboard"

	cloudstore "cloud.google.com/go/storage"
	"github.com/emicklei/tre"
	"golang.org/x/net/context"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

func main() {
	flag.Parse()
	if len(flag.Args()) < 2 {
		fmt.Println("kiya [flags] [profile] [get|put|delete|list|template|copy|paste] [|parent/key] [|value] [|template-filename]")
		fmt.Println("    if value or template-filename is needed, but missing, it is read from stdin")
		flag.PrintDefaults()
		os.Exit(0)
	}
	// Create the KMS client.
	kmsService, err := cloudkms.New(newAuthenticatedClient())
	if err != nil {
		log.Fatal(err)
	}
	// Create the Bucket client
	storageService, err := cloudstore.NewClient(context.Background())
	if err != nil {
		log.Fatalf("failed to create client [%v]", err)
	}
	profileName := flag.Arg(0)
	target, ok := profiles[profileName]
	if !ok {
		log.Fatalf("no such profile [%s] please check your .kiya.json file", profileName)
	}
	// what command?
	switch flag.Arg(1) {

	case "put":
		key := flag.Arg(2)
		value := valueOrReadFrom(flag.Arg(3), os.Stdin)
		command_put_paste(kmsService, storageService, target, "put", key, value)

	case "paste":
		key := flag.Arg(2)
		value, err := clipboard.ReadAll()
		if err != nil {
			log.Fatal(tre.New(err, "clipboard read failed", "key", key))
		}
		command_put_paste(kmsService, storageService, target, "paste", key, value)

	case "copy":
		key := flag.Arg(2)
		value, err := getValueByKey(kmsService, storageService, key, target)
		if err != nil {
			log.Fatal(tre.New(err, "get failed", "key", key, "err", err))
		}
		if err := clipboard.WriteAll(value); err != nil {
			log.Fatal(tre.New(err, "copy failed", "key", key, "err", err))
		}

	case "get":
		key := flag.Arg(2)
		value, err := getValueByKey(kmsService, storageService, key, target)
		if err != nil {
			log.Fatal(tre.New(err, "get failed", "key", key, "err", err))
		}
		fmt.Println(value)

	case "delete":
		command_delete(kmsService, storageService, target)
	case "list":
		command_list(storageService, target)
	case "template":
		command_template(kmsService, storageService, target)
	default:
		fmt.Println("unknown command", flag.Arg(1))
	}
}
package main

import (
	"bytes"
	"crypto/rc4"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
)

var (
	file = flag.String("file", "", "file to encrypt")
	key  = flag.String("key", "1337", "key used to encrypt the file")
)

func Rc4EncryptOrDecrypt(data []byte, key []byte) error {

	cipher, err := rc4.NewCipher(key)

	if err != nil {
		return err
	}

	cipher.XORKeyStream(data, data)

	return nil
}

func main() {

	flag.Parse()

	if *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	f, err := os.OpenFile(*file, os.O_RDWR, 0)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	finfo, err := f.Stat()

	if err != nil {
		log.Fatal(err)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(finfo.Size()), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)

	if err != nil {
		log.Fatal(err)
	}

	ef, err := elf.NewFile(bytes.NewReader(data))

	if err != nil {
		if err == io.EOF {
			fmt.Println("[!] not an elf file")
			os.Exit(1)
		}

		log.Fatal(err)
	}

	for _, s := range ef.Sections {
		if s.Name == ".text" || s.Name == ".rodata" {
			Rc4EncryptOrDecrypt(data[s.Addr:s.Addr+s.Size], []byte(*key))
		}
	}

	if syscall.Munmap(data) != nil {
		log.Fatal(err)
	}
}

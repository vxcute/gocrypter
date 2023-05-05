package main

import (
	"bytes"
	"crypto/rc4"
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

var (
	file = flag.String("file", "", "file to encrypt")
	key  = flag.String("key", "1337", "key used to encrypt the file")
)

var stub = []byte{
	0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0x18, 0x00, 0x00, 0x00,
	0xba, 0x05, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05,
	0xbf, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
	0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x20, 0x53, 0x4f, 0x59, 0x20, 0x42, 0x4f,
	0x59,
}

func Rc4EncryptOrDecrypt(data []byte, key []byte) error {

	cipher, err := rc4.NewCipher(key)

	if err != nil {
		return err
	}

	cipher.XORKeyStream(data, data)

	return nil
}

func Base[T any](v []T) unsafe.Pointer {
	return unsafe.Pointer(&v[0])
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
		fmt.Println(err)
		os.Exit(1)
	}

	elfh := (*elf.Header64)(Base(data))

	ccave := 0
	ccaveSize := 0

	for _, p := range ef.Progs {

		if p.Type == elf.PT_LOAD {
			if ccave != 0 {
				ccaveSize = int(p.Off) - ccave
				break
			}

			if (p.Flags & elf.PF_X) != 0 {
				ccave = int(p.Off) + int(p.Filesz)
			}
		}
	}

	elfh.Entry = uint64(ccave)

	if ccaveSize > len(stub) {
		for i := 0; i < len(stub); i++ {
			data[ccave+i] = stub[i]
			fmt.Printf("0x%x, ", data[ccave+i])
		}
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

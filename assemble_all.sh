#!/bin/bash
echo "Assembling all HeavyThing v1.14 binaries..."
for p in {dhtool,hnwatch,rwasa,sshtalk,toplip,webslap}; do
	echo "$p..."
	cd $p
	fasm -m 262144 $p.asm && ld -o $p $p.o
	cd ..
done
cd webslap
echo "webslap_tlsmin..."
fasm -m 262144 webslap_tlsmin.asm && ld -o webslap_tlsmin webslap_tlsmin.o
cd ..
cd rwasa
echo "rwasa_tlsmin..."
fasm -m 262144 rwasa_tlsmin.asm && ld -o rwasa_tlsmin rwasa_tlsmin.o
cd ..
cd util
for p in {bigint_tune,make_dh_static,mersenneprimetest}; do
	echo "util/$p..."
	fasm -m 262144 $p.asm && ld -o $p $p.o
done
cd ..
cd examples
for p in {echo,hello_world,minigzip,multicore_echo,sha256,sshecho,tlsecho,tuieffects,tuimatrix}; do
	echo "examples/$p..."
	cd $p
	fasm -m 262144 $p.asm && ld -o $p $p.o
	cd ..
done
# our C/C++ examples
echo "C/C++ Integration and Mixing, examples/hello_world_c1..."
cd hello_world_c1
fasm -m 262144 ht.asm
gcc -nostdlib -o hello hello.c ht.o
cd ..
cd hello_world_c2
echo "C/C++ Integration and Mixing, examples/hello_world_c2..."
fasm -m 262144 ht.asm
gcc -nostdlib -o hello hello.c ht.o
cd ..
echo "C/C++ Integration and Mixing, examples/simplechat_c++..."
cd simplechat_c++
fasm -m 262144 ht.asm
g++ -std=c++11 -o simplechat simplechat.cpp ht.o
cd ..
echo "C/C++ Integration and Mixing, examples/simplechat_ssh_auth_c++..."
cd simplechat_ssh_auth_c++
fasm -m 262144 ht.asm
g++ -std=c++11 -o simplechat_ssh simplechat_ssh.cpp ht.o
cd ..
echo "C/C++ Integration and Mixing, examples/simplechat_ssh_c++..."
cd simplechat_ssh_c++
fasm -m 262144 ht.asm
g++ -std=c++11 -o simplechat_ssh simplechat_ssh.cpp ht.o
cd ..
echo "Done."

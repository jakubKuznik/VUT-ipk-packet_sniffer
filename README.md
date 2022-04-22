# Packet Sniffer (VUT FIT IPK)

Jednoduchá terminálová aplikace packet sniffer, přesněji Frame sniffer. Odchytává ethernetové rámce na zadáném síťovém rozhraní a vypisuje je na standardní výstup. Program je navržen pro unixové systémy.

- Sniffer pracuje jak s ipv4 tak ipv6 pakety.

- Sniffer obsahuje podrobnou dokumentaci o jeho fungování: manual.pdf


### Build 

```sh
make
```

### Clean build

```sh
make clean
make
```

## Spuštění 
```sh
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} {-h | --help}
```
- V případě že není vybrané síťové rozhraní, tak program vypíše veškeré síťové rozhraní na standardní výstup. 
- Není-li zvolen filtr na protokol, tak se vypisují veškeré protokoly, které sniffer umí rozpoznat.
- -n udává počet paketů, které se vypíší. Chybí-li tento parametr vypíše se jenom jeden
- V rámci protokolu TCP a UDP lze přidat omezení na port (-p), ten funguje jak na source, tak destination port


## Příklady spouštení 

```sh
./ipk-sniffer # vypíše seznam síťových rozhraní na stdout  
```
```sh
./ipk-sniffer -i # vypíše seznam síťových rozhraní na stdout  
```
```sh 
# vypíše 1 udp rámec, který získá na rozhraní eth0, na stdout 
./ipk-sniffer -i eth0 --udp 
```
```sh
# vypíše 10 udp, nebo arp rámců, který získá na rozhraní eth0, na stdout.
./ipk-sniffer -i eth0 --udp --arp -n 10 
```

```sh
# vypíše 10 udp, nebo arp rámců, který získá na rozhraní eth0, na stdout.
./ipk-sniffer -i eth0 --udp --arp -n 10 
```

```sh
# vypíše 100 udp, arp, nebo icmp rámců, který získá na rozhraní eth0, příčemž udp rámce musí mít zdrojový nebo cílový port 43. 
./ipk-sniffer -i eth0 --udp --arp --icmp -n 10 -p 43
```

## Výstupní formát 

```sh
## Informace získané z hlaviček packetů
timestamp: 2022-04-22T11:15:48.593+02:00        # Čas v RFC3339
src MAC: c0:06:c3:02:ed:6a                      # Zdrojová MAC adresa
dst MAC: 01:00:5e:7f:ff:fa                      # Cílová mac addres
frame lenght: 54                                # Délká rámce v Bytech
src IP: 192.168.1.105                           # Zdrová ip adresa   
dst IP: 8.8.8.8                                 # Cílová ip adresa 
### zde končí společná část všech typů rámců 
src port: 39496                                 # Zdrojový port
dst port: 1900                                  # Cílový port
Protocol: UDP                                   # informace navíc 
## ofset + data celého rámce 

0x0000:  01 00 5e 7f ff fa c0 06  c3 02 ed 6a 08 00 45 00 ..^.... ...j..E..
0x0010:  00 c9 fb 49 40 00 01 11  cb ce c0 a8 01 69 ef ff ...I@... .....i...
0x0020:  ff fa 9a 48 07 6c 00 b5  ad b6 4d 2d 53 45 41 52 ...H.l.. ..M-SEAR.
0x0030:  43 48 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48 CH * HTT P/1.1..H.
```
# mkssl
一键创建自签名证书，需要手动信任根证书。

Usage:
 ./mkssl -h                               print Usage 
 ./mkssl -c IP/Domain Name                only create key and csr 
 ./mkssl -d a.cer                         convert cer to crt
 ./mkssl -p a.crt a.key ca.crt            convert to pfx 
 ./mkssl -s a.pfx                         convert pfx to crt and key
 ./mkssl 10.96.0.1                        sign certificate for ip
 ./mkssl a.b.c                            sign certificate for a domain name
 ./mkssl *.b.c                            sign certificate for root domain

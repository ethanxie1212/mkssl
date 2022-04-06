#!/bin/bash
#name:mksslv3.sh
#date:2021.12.28
#author:ethan.xie
#function:create self_sign ca and server certificate 
####################################################################
#update:
#add cer convert function
#known bug:
#sign root domain will be error after signed a same domain name 
####################################################################

check_ip() {
	IP=$1
    	if [[ ${IP} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		N1=$(echo $IP|cut -d. -f1)
		N2=$(echo $IP|cut -d. -f2)
		N3=$(echo $IP|cut -d. -f3)
		N4=$(echo $IP|cut -d. -f4)
		if [[ ${N1} -le 255 ]] && [[ ${N2} -le 255 ]] && [[ ${N3} -le 255 ]] && [[ ${N4} -le 255 ]]; then
			SAN=IP.1
		else
			echo -e "\e[1;31m  " [${IP}] is not a valid ip or domain name ! " \e[0m" && exit 1
		fi
	else
		DN=$(echo $IP|awk -F '.' '{print $3}')
		[[ -z ${DN} ]] && echo -e "\e[1;31m  " [${IP}] is not a valid ip or domain name ! " \e[0m" && exit 1
		SAN=DNS.1
	fi
}

create_ca() {
	mkdir -p ${DIR} && cd ${DIR}
	echo "$TIME $1" >> ${DIR}/cert_list
	cat > ca.csr <<-EOF
	[req]
	default_bits = 4096
	prompt = no
	default_md = sha256
	distinguished_name = dn 
	x509_extensions = usr_cert

	[ dn ]
	C=CN
	ST=Shanghai
	L=Shanghai
	O=AISHU
	OU=IT
	emailAddress=xiehouyao@gmail.com
	CN = AISHU ROOT CA

	[ usr_cert ]
	basicConstraints=CA:TRUE
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid,issuer 
	EOF
	
	#sign ca
	openssl genrsa -out ca.key 4096 > /dev/null 2>&1
	openssl req -new -x509 -key ca.key -days 730 -out ca.crt -config ca.csr
}

#generate conf
gen_conf() {
	cat > $1.answer <<-EOF
	[req]
	default_bits = 4096
	prompt = no
	default_md = sha256
	x509_extensions = req_ext
	req_extensions = req_ext
	distinguished_name = dn

	[ dn ]
	C=CN
	ST=Shanghai
	L=Shanghai
	O=AISHU
	OU=IT
	emailAddress=xiehouyao@gmail.com
	CN = $1

	[ req_ext ]
	subjectAltName = @alt_names

	[ alt_names ]
	$SAN = $1
	EOF
	
	#crate csr and key file
	openssl genrsa -out $1.key 4096 > /dev/null 2>&1
	openssl req -new -key $1.key -out $1.csr -config $1.answer
}

sign_certificate() {
	openssl x509 -req -in $1.csr -CA $DIR/ca.crt -CAkey $DIR/ca.key -CAcreateserial \
	-out $1.crt -days 730 -extensions 'req_ext' \
	-extfile $1.answer > /dev/null 2>&1
	
	#bund certificate
	mv $1.crt $1.certonly.crt
	cat $1.certonly.crt $DIR/ca.crt > $1.crt
}

convert() {
	#convert to pfx
	openssl pkcs12 -export -out $1.pfx -inkey $1.key -in $1.crt -certfile $DIR/ca.crt -password pass:eisoo.com > /dev/null 2>&1
	#convert to pem
	openssl pkcs12 -in $1.pfx -nodes -out $1.pem -passin pass:eisoo.com > /dev/null 2>&1
}

verify(){
	#verify
	#SAN=$(openssl x509 -in $1.crt -noout -text |grep -Ei "dns|ip")
	STATUS=$(openssl verify -CAfile $DIR/ca.crt $1.crt)
	L1=$(echo ${STATUS}|awk -F ':' '{print $1}')
	CERTS=$(cat $DIR/cert_list)
	NO=$(cat $DIR/cert_list|wc -l)
	echo
	echo -e "  ${L1} \e[1;32m OK \e[0m"
	echo
	echo "======================================="
	echo -e "\e[1;32m  "Already Singed ${NO} Certificate[s]：" \e[0m"
	CERTS=$(cat $DIR/cert_list)
	echo "${CERTS}"
	echo "======================================="
	echo
}

#clean temp file
clean() {
	rm -rf $DIR/ca.csr
	rm -rf $DIR/ca.srl
	rm -rf $RUN_DIR/$1/$1.answer
	rm -rf $RUN_DIR/$1/$1.certonly.crt
	rm -rf $RUN_DIR/$1/$1.csr
}

usage() {
	echo
        echo "Usage:"
        echo " ./mkssl -h                               print Usage "
        echo " ./mkssl -c IP/Domain Name                only create key and csr "
        echo " ./mkssl -d a.cer                         convert cer to crt"
        echo " ./mkssl -p a.crt a.key ca.crt            convert to pfx "
        echo " ./mkssl -s a.pfx                         convert pfx to crt and key"
        echo " ./mkssl 10.96.0.1                        sign certificate for ip"
        echo " ./mkssl a.b.c                            sign certificate for a domain name"
        echo " ./mkssl *.b.c                            sign certificate for root domain"
        echo
        exit 0
}

create_csr_key() {
	check_ip $1
	#create dir
        [[ ! -d ${RUN_DIR}/$1 ]] && mkdir -p ${RUN_DIR}/$1
        cd ${RUN_DIR}/$1
        gen_conf $1
        rm -rf $RUN_DIR/$1/$1.answer
        echo -e "  \e[1;32m OK \e[0m"
        exit 0
}

cer_convert() {
	TYPE=$(file $1|awk '{print $2}')
	[[ ${TYPE} == "PEM" ]] && openssl x509 -inform PEM -in $1 -out $1.crt
	[[ ${TYPE} == "data" ]] && openssl x509 -inform DER -in $1 -out $1.crt
	echo -e "  $1.crt : \e[1;32m OK \e[0m" && exit 0
}

pfx_convert() {
	openssl pkcs12 -in  $1 -nodes -out $1.pem
	openssl x509 -in $1.pem -out $1.crt
	openssl rsa -in $1.pem -out $1.key
	echo -e "  $1.crt : \e[1;32m OK \e[0m"
	echo -e "  $1.key : \e[1;32m OK \e[0m"
	rm -rf $1.pem && exit 0
}

convert_pfx() {
	openssl pkcs12 -export -out $1.pfx -inkey $2 -in $1 -certfile $3 -password pass:eisoo.com > /dev/null 2>&1
	echo -e "  $1.pfx : \e[1;32m OK \e[0m" && exit 0
}

##################################-main-###################################
#define 
RUN_DIR=$(dirname $(readlink -f "$0"))
DIR=${RUN_DIR}/ca
TIME=$(date)

#usage check
[[ "$#" -ne 1 ]] && [[ "$#" -ne 2 ]] && [[ "$#" -ne 4 ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 2 ]] && [[ "$1" != "-c" ]] && [[ "$1" != "-d" ]] && [[ "$1" != "-s" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 1 ]] && [[ "$1" == "-c" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 1 ]] && [[ "$1" == "-d" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 1 ]] && [[ "$1" == "-s" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 1 ]] && [[ "$1" == "-p" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$#" -eq 4 ]] && [[ "$1" != "-p" ]] && echo -e "\e[1;31m  "ERR:  use ' [-h]' for help ！ " \e[0m" && exit 1
[[ "$1" == "-h" ]] && usage
[[ "$1" == "-c" ]] && create_csr_key $2
[[ "$1" == "-d" ]] && cer_convert $2
[[ "$1" == "-s" ]] && pfx_convert $2
[[ "$1" == "-p" ]] && convert_pfx $2 $3 $4

#create ca and sign certificate
check_ip $1
#create ca or not
if [[ ! -d ${DIR} ]];then
	create_ca $1
else
	echo -e "\e[1;33m  "Find CA, Skip" \e[0m"
	echo "$TIME $1" >> ${DIR}/cert_list
fi
	
#create dir
[[ ! -d ${RUN_DIR}/$1 ]] && mkdir -p ${RUN_DIR}/$1
cd ${RUN_DIR}/$1

gen_conf $1
sign_certificate $1
convert $1
clean $1
verify $1

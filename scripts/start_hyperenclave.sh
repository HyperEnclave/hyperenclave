#!/bin/bash

CMDLINE=/proc/cmdline

YELLOW="\e[33m"
NC="\e[0m"

function get_memmap_parameter()
{
	for i in $(cat $CMDLINE)
	do
		if [[ "$i" =~ "memmap=" ]];then
			# multi memory ranges
			str_mmap=($(echo $i | awk -F"[=,]" '{for(i=2;i<=NF;i++)printf("%s ",$i);}'))
			break
		fi
	done

	flag=1
	for((i=0;i<${#str_mmap[*]};i++));
	do
		str=${str_mmap[$i]}
		tmp=$(echo $str | awk -F"[$ ]" '/[0-9a-fA-FxX]+[KMG]?\$[0-9a-fA-FxX]+[KMG]?/\
			{printf("%s,%s",$2,$1);}')

		if [ "$tmp" != "" ];then
			if [ $flag -eq 1 ];then
				res+=$tmp
				flag=0
			else
				res+=,$tmp
			fi
		fi
	done

	if [ "$res" = "" ];then
		echo "ERROR"
	else
		echo "$res"
	fi
}

sudo sysctl dev.hyper_enclave.enabled=0
sudo rmmod hyper_enclave

res=$(get_memmap_parameter)
if [ "$res" = "ERROR" ];then
	echo "ERROR. Please use correct memmap parameter: memmap=nn[KMG]$ss[KMG]"
else
	feature_mask=0x302
	sudo insmod ../../hyperenclave-driver/driver/hyper_enclave.ko str_memmap=$res feature_mask=$feature_mask
	sudo sysctl dev.hyper_enclave.enabled=1
fi

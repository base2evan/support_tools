#!/bin/bash

set -e

jq_path=`pwd`
mashery_url=$1
security_group="sg-1fa5ae7d"
security_group2="sg-d24a40b0"
rules=0
if [[ $1 == '' ]]
then
	echo "Usage: ./update_mashery_ips.sh <mashery_ip_list_url"
	exit
fi
if [[ ! -e /usr/local/bin/aws ]]
then
	echo "ERROR: AWS CLI Must be installed. Please run \"pip install awscli\""
	exit
fi
if [[ ! -e $jq_path ]]
then
	echo "ERROR: \"jq\" (http://stedolan.github.io/jq/) must be installed. Are you in the folder that you unzipped the tool into?"
	exit
fi
if [[ ! -e update_mashery_ips.sh ]]
then
	echo "ERROR: \"update_mashery_ips.sh\" must be called from the directory that it's located in"
	exit
fi
if [[ `hostname -s` != 'nat01' ]]
then
        echo "ERROR: \"update_mashery_ips.sh\" must be called from nat01.prod.aws.dubber.net"
        exit
fi


echo "STATUS: Downloading Mashery IP List from $1"
wget $1 -O /tmp/mashery_ips.txt
sed -i 's/[ \t]*$//' /tmp/mashery_ips.txt 
ip_whitelist=""
ip_whitelist2=""
IFS=$'\n'
echo "STATUS: Iterating through list and compiling IP whitelist"
echo -n "PROGRESS: "
for i in `cat /tmp/mashery_ips.txt`
do
	echo -n "#"
        if [[ `echo $i | cut -c 1` != "#" ]]
        then
                ip_addr=`echo $i|cut -d / -f 1`
		if [[ $ip_whitelist =~ "$ip_addr" ]]
	        then
			echo -n "D"
		else
			rules=$((rules+1))
		        if [[ $i =~ "/" ]]
        	        then
				ip_mask=`echo $i|cut -d / -f 2| cut -c 1-2`
			else
        	                ip_mask="32"
	                fi
			if [[ $rules -lt 51 ]]
			then
	        	        ip_whitelist="$ip_whitelist { \"CidrIp\" : \"$ip_addr/$ip_mask\" },"
			else
                                ip_whitelist2="$ip_whitelist2 { \"CidrIp\" : \"$ip_addr/$ip_mask\" },"
			fi
		fi
        fi
done
echo "DONE"
echo -n "STATUS: "
echo -n $rules 
echo " rules in total"
ip_whitelist=${ip_whitelist%?}
echo "STATUS: Generating payload"
payload="{ \"IpProtocol\" : \"tcp\", \"FromPort\" : 443, \"ToPort\" : 443, \"IpRanges\" : [ $ip_whitelist ] }"
if [[ $ip_whitelist2 != '' ]]
then
	echo "STATUS: More than 50 rules, processing second payload"
	ip_whitelist2=${ip_whitelist2%?}
	payload2="{ \"IpProtocol\" : \"tcp\", \"FromPort\" : 443, \"ToPort\" : 443, \"IpRanges\" : [ $ip_whitelist2 ] }"
fi
echo "STATUS: Getting list of current rules to purge"
/usr/local/bin/aws ec2 describe-security-groups --region ap-southeast-2 --group-id $security_group > /tmp/$security_group
/usr/local/bin/aws ec2 describe-security-groups --region ap-southeast-2 --group-id $security_group2 > /tmp/$security_group2
echo "STATUS: Processing list"
cat /tmp/$security_group | $jq_path/jq '.SecurityGroups[0].IpPermissions' >/tmp/$security_group-perms
cat /tmp/$security_group2 | $jq_path/jq '.SecurityGroups[0].IpPermissions' >/tmp/$security_group2-perms
if [[ `cat /tmp/$security_group-perms` == "[]" ]]
then
	echo "STATUS: No existing rules from $security_group to revoke!"
else
	echo "STATUS: Revoking existing rules from $security_group"
	/usr/local/bin/aws ec2 revoke-security-group-ingress --region ap-southeast-2 --group-id $security_group --ip-permissions file:///tmp/$security_group-perms
fi
if [[ `cat /tmp/$security_group2-perms` == "[]" ]]
then
        echo "STATUS: No existing rules from $security_group2 to revoke!"
else
        echo "STATUS: Revoking existing rules from $security_group2"
        /usr/local/bin/aws ec2 revoke-security-group-ingress --region ap-southeast-2 --group-id $security_group2 --ip-permissions file:///tmp/$security_group2-perms
fi
echo "STATUS: Adding new IP whitelist for $security_group"
/usr/local/bin/aws ec2 authorize-security-group-ingress --region ap-southeast-2 --group-id $security_group --ip-permissions $payload
if [[ $ip_whitelist2 != '' ]]
then 
	echo "STATUS: Adding new IP whitelist for $security_group2"
	/usr/local/bin/aws ec2 authorize-security-group-ingress --region ap-southeast-2 --group-id $security_group2 --ip-permissions $payload2
fi
echo "STATUS: Cleaning up"
rm /tmp/mashery_ips.txt
rm /tmp/$security_group
rm /tmp/$security_group-perms
rm /tmp/$security_group2
rm /tmp/$security_group2-perms
echo "STATUS: Done!"

#!/bin/bash

target=$1
domain=$(echo $target | rev)
# domains enum
assetfinder $target -subs-only | tee -a assetfinder_$target
crtsh --domain $target | tee -a crtsh_$target
findomain --target $target | tee finddomain_$1
subfinder -d $target | tee subfinder_$target
github-subdomains -d $target -t <TOKEN> | tee github_subdomains_$target
cat github_subdomains_$target | rev | grep $domain | rev | grep -v Domain | grep -v keyword | grep -v https | awk '{print$2}' > tmp
mv tmp github_subdomains_$target
cat *_$target | sort -u > allsubs.txt
rm *_$target

# find a way to remove aws and other clouds from asn look up to include to live sub checks
amass enum -d $target -o enum.amass
cat enum.amass | grep ASN | awk '{print $1}' | sed '175d;159d;14d;15d;20d;24d;25d;65d;79d;109d;110d;116d;121d' | sed 's/[^ ]* */AS&/g' | sort -u | sed 's/\x1b\[[0-9;]*m//g' > asn.list
while IFS= read -r line; do
        whois -h whois.radb.net -- "-i origin $line" | grep -Eo "([0-9.]+){4}/[0-9]+" >> netblocks.list
done < asn.list
cap="${target^}"
cap=$(echo "$cap" | sed 's/.com//g')
cat asn.list | grep "descr:          $cap" -A 1 | grep AS | awk '{print $2}' | sort -u
awk -v term="$cap" '$0 ~ term {print prev} {prev=$0}' asn.list | awk '{print $2}' >> netblocks.txt
sort -u netblocks.txt > tmp && mv tmp netblocks.txt
cat netblocks.txt | mapcidr > ips.txt
cat ips.txt | dnsx -ptr -resp-only | sort -u >> newsubs.txt
cat newsubs.txt | anew -q allsubs.txt
sort -u allsubs.txt > tmp.txt
mv tmp.txt allsubs.txt
# check Live Subs

cat allsubs.txt | httprobe | tee alivesubs.txt

# header capture
cat alivesubs.txt | aquatone -chrome-path /usr/bin/chromium -out headers
#!/bin/bash

# Etap 1 - rozpakowanie spakowanych plików z danego dnia/godziny do katalogu ./uncompressed
# Uruchomić w parametrem np. 2020-12-10_ albo 2020-12-11_11
echo $1

mkdir -p uncompressed

FILES=/home/sniffer/data/$1*
for f in $FILES
do
  echo "Unzipping $f file..."
  7z x "$f" -aos -ouncompressed
done

# Etap 2 - uruchomienie pcap2db dla każdego pliku .pcap i zapisanie wyjścia do pliku .log
# W pliku pcap2db trzeba było zamienić w ostatniej linijce $(basename $1).ndjsonf na $(basename $1).json.ndjsonf

mkdir -p wrzucanie_logs

FILES=uncompressed/$1*
for f in $FILES
do
  current_date_time="`date +%Y-%m-%d_%H:%M:%S`";
  echo "[$current_date_time] Processing $f file..."
  ./pcap2db "$f" |& tee "./wrzucanie_logs/$(basename $f).log"                     # zwykły albo
  # ./pcap2db_multiproc "$f" 2>&1 |& tee "./wrzucanie_logs/$(basename $f).log"    # multiproc
done

#!/bin/bash

for curr_csv_file in `ls UNSW-NB15_[1234].csv`
do
    echo "processing, ${curr_csv_file}"
    n_total=`cat ${curr_csv_file} | wc -l`
    echo "total rows,${n_total}"
    
    cut -d, -f 49 ${curr_csv_file} > /tmp/cut.output

    while read -r curr_label
    do
        n_label_occurrences=`grep "${curr_label}" /tmp/cut.output | wc -l`
        echo ${curr_label},${n_label_occurrences} | tr -d '\r'
    done < <(sort -u /tmp/cut.output)
done

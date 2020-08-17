# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 22:47:49 2020

@author: Rolando Inglés
"""

import re
import pandas as pd
from pathlib import Path
import unsw_nb15_utils as unswutils

RETURN_NOT_OK=-1
RETURN_OK=0


global_tags_list = ('5K', '10K', '25K', '50K', '100K')

##
# UNSB-NB15_1.csv contains three  unexpected chars at the beginning of the
# file, namely:
#       00000000  ef bb bf 35 39 2e 31 36  36 2e 30 2e 30 2c 31 33  |...59.166.0.0,13|
#       00000010  39 30 2c 31 34 39 2e 31  37 31 2e 31 32 36 2e 36  |90,149.171.126.6|
# #

global_input_files_dict = {
    '00': {'filename': r'UNSW-NB15_1.csv', 'n_lines_to_skip': 1},
    '01': {'filename': r'UNSW-NB15_2.csv', 'n_lines_to_skip': 0}, 
    '02': {'filename': r'UNSW-NB15_3.csv', 'n_lines_to_skip': 0},
    '03': {'filename': r'UNSW-NB15_4.csv', 'n_lines_to_skip': 0}
}

##
# NOTE:
# The file UNSW-NB15_1.csv contains "Backdoors" as one of the attacks reference,
# nevertheless, the others contains "Backdoor" (no 's' at the end)
##
global_labels_dict = {
    '00': {',,0': {'5K': 2463, '10K': 5050, '25K': 8669, '50K': 15256, '100K': 27313},
           ',.*Analysis.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Backdoors.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*DoS.*,1': {'5K': 50, '10K': 100, '25K': 150, '50K': 200, '100K': 250},
           ',.*Exploits.*,1': {'5K': 100, '10K': 200, '25K': 300, '50K': 400, '100K': 500},
           ',.*Fuzzers.*,1': {'5K': 50, '10K': 125, '25K': 250, '50K': 500, '100K': 1000},
           ',.*Generic.*,1': {'5K': 100, '10K': 200, '25K': 400, '50K': 800, '100K': 1600},
           ',.*Reconnaissance.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Shellcode.*,1': {'5K': 15, '10K': 25, '25K': 50, '50K': 75, '100K': 100},
           ',.*Worms.*,1': {'5K': 3, '10K': 5, '25K': 10, '50K': 15, '100K': 20}},
    '01': {',,0': {'5K': 1580, '10K': 3340, '25K': 6370, '50K': 12741, '100K': 25482},
           ',.*Analysis.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Backdoor.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*DoS.*,1': {'5K': 50, '10K': 100, '25K': 150, '50K': 200, '100K': 250},
           ',.*Exploits.*,1': {'5K': 100, '10K': 200, '25K': 300, '50K': 400, '100K': 500},
           ',.*Fuzzers.*,1': {'5K': 50, '10K': 125, '25K': 250, '50K': 500, '100K': 1000},
           ',.*Generic.*,1': {'5K': 100, '10K': 200, '25K': 400, '50K': 800, '100K': 1600},
           ',.*Reconnaissance.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Shellcode.*,1': {'5K': 15, '10K': 25, '25K': 50, '50K': 75, '100K': 100},
           ',.*Worms.*,1': {'5K': 3, '10K': 5, '25K': 10, '50K': 15, '100K': 20}}, 
    '02': {',,0': {'5K': 1580, '10K': 3340, '25K': 6360, '50K': 12580, '100K': 24900},
           ',.*Analysis.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Backdoor.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*DoS.*,1': {'5K': 50, '10K': 100, '25K': 150, '50K': 200, '100K': 250},
           ',.*Exploits.*,1': {'5K': 100, '10K': 200, '25K': 300, '50K': 400, '100K': 500},
           ',.*Fuzzers.*,1': {'5K': 50, '10K': 125, '25K': 250, '50K': 500, '100K': 1000},
           ',.*Generic.*,1': {'5K': 100, '10K': 200, '25K': 400, '50K': 800, '100K': 1600},
           ',.*Reconnaissance.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Shellcode.*,1': {'5K': 15, '10K': 25, '25K': 50, '50K': 75, '100K': 100},
           ',.*Worms.*,1': {'5K': 3, '10K': 5, '25K': 10, '50K': 15, '100K': 20}}, 
    '03': {',,0': {'5K': 1580, '10K': 3340, '25K': 6360, '50K': 12580, '100K': 24900},
           ',.*Analysis.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Backdoor.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*DoS.*,1': {'5K': 50, '10K': 100, '25K': 150, '50K': 200, '100K': 250},
           ',.*Exploits.*,1': {'5K': 100, '10K': 200, '25K': 300, '50K': 400, '100K': 500},
           ',.*Fuzzers.*,1': {'5K': 50, '10K': 125, '25K': 250, '50K': 500, '100K': 1000},
           ',.*Generic.*,1': {'5K': 100, '10K': 200, '25K': 400, '50K': 800, '100K': 1600},
           ',.*Reconnaissance.*,1': {'5K': 25, '10K': 50, '25K': 75, '50K': 150, '100K': 300},
           ',.*Shellcode.*,1': {'5K': 15, '10K': 25, '25K': 50, '50K': 75, '100K': 100},
           ',.*Worms.*,1': {'5K': 3, '10K': 5, '25K': 10, '50K': 15, '100K': 20}}
 }   

##
# @name get_rows_by_label_into_output_file
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def cp_lines_by_label(output_filename="output.csv",
                      input_filename='input.csv', 
                      label_to_get='nolabel',
                      n_lines_to_cp=0,
                      n_lines_to_skip=0):
    print('copying %d %s\'s lines into %s' % 
          (n_lines_to_cp, label_to_get, output_filename))

    line_cnt = 0
                # e.g. ,Benign$
    
    reg_expr = label_to_get.replace(' ', r'\s')+'$'
    #reg_expr = reg_expr.replace(' ', r'\s')
 
    # could be needed os.path.join
    # python 3 from pathlib import Path
    
    with open(output_filename, 'a') as csv_output_file:
        with open(input_filename) as csv_input_file:
            # skipping lines
            for _ in range(n_lines_to_skip):
                next(csv_input_file)
                
            for input_line in csv_input_file:
                if re.search(reg_expr, input_line):
                    csv_output_file.write(input_line)
                    line_cnt += 1
                    if line_cnt == n_lines_to_cp:
                        return line_cnt

    return line_cnt

##
# @name generate_train_test_sets
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def copy_header_into_output_csv(output_filename=''):
    if Path('NUSW-NB15_features.csv').is_file():
        with open(output_filename, 'w') as csv_output_file:
            features_df = pd.read_csv('NUSW-NB15_features.csv', encoding='ANSI')
    
            col_names_series = features_df['Name']
            features_names = ','.join(col_names_series.values.tolist())
            
            csv_output_file.write(features_names)
            csv_output_file.write('\n')
    else:
        return RETURN_NOT_OK
    
    return RETURN_OK
    
##
# @name generate_train_test_sets
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def generate_train_test_sets(output_file_tag="notag"):
    
    task_output_filename = unswutils.get_unsw_nb15_output_filename(output_file_tag)
    
    # creating or truncating file by copying the features header
    if copy_header_into_output_csv(task_output_filename) == RETURN_NOT_OK:
        return RETURN_NOT_OK
    
    for file_key, file_dict in global_input_files_dict.items():
        task_input_csv_filename = file_dict['filename']
        n_lines_to_skip = file_dict['n_lines_to_skip']
        
        if not file_key in global_labels_dict:
            continue
        
        processing_labels_dict = global_labels_dict[file_key]
        
        for label_key, label_val in processing_labels_dict.items():
            processing_tags_dict = label_val
            
            if not output_file_tag in processing_tags_dict:
                continue
            
            n_lines_to_cp = processing_tags_dict[output_file_tag]

            n_sent_lines =  cp_lines_by_label(task_output_filename,
                                               task_input_csv_filename,
                                               label_key,
                                               n_lines_to_cp,
                                               n_lines_to_skip)
            
            if n_sent_lines == n_lines_to_cp:
                print('OK')
            else:
                print('ERROR: %d != %d, file_key=%s, label_key=%s, label_val=%s'
                      % (n_sent_lines, n_lines_to_cp, file_key, label_key, label_val))
                return RETURN_NOT_OK
    return RETURN_OK            

##
# @name clean_output_files
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def main():
    for output_file_tag in global_tags_list:
        if RETURN_OK == generate_train_test_sets(output_file_tag):
            print('done!')
        else:
            print('something went wrong generating the %s file' % output_file_tag)
            return RETURN_NOT_OK
                
if __name__ == "__main__":
    main()


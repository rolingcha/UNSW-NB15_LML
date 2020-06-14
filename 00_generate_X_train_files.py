# -*- coding: utf-8 -*-
"""
Created on Fri Jun 12 10:51:28 2020

@author: Rolando Inglés
"""

import re

RESULT_OK=0
RESULT_NOT_OK=-1

_ric_global_processing_dict = {
	'rolingcha.csv' : 
        {'5K': {'Benign': 2, 'DoS attacks-Hulk': 2, 
                'DoS attacks-SlowHTTPTest': 2}},
}

global_processing_tags = ('5K', '10K')   

global_processing_dict = {
    'UNSW-NB15_1.csv' :
        {'5K': {',,0': 2463,
                ',.*Analysis.*,1': 25,
                ',.*Backdoors.*,1': 25,
                ',.*DoS.*,1': 50,
                ',.*Exploits.*,1': 100,
                ',.*Fuzzers.*,1': 50,
                ',.*Generic.*,1': 100,
                ',.*Reconnaissance.*,1': 25,
                ',.*Shellcode.*,1': 15,
                ',.*Worms.*,1': 4},
         '10K': {',,0': 5050,
                 '.*Analysis.*,1': 50,
                 '.*Backdoors.*,1': 50,
                 '.*DoS.*,1': 100,
                 '.*Exploits.*,1': 200,
                 '.*Fuzzers.*,1': 125,
                 '.*Generic.*,1': 200,
                 '.*Reconnaissance.*,1': 50,
                 '.*Shellcode.*,1': 25,
                 '.*Worms.*,1': 8}},
    'UNSW-NB15_2.csv' :
        {'5K': {',,0': 1580,
                ',.*Analysis.*,1': 25,
                ',.*Backdoor.*,1': 25,
                ',.*DoS.*,1': 50,
                ',.*Exploits.*,1': 100,
                ',.*Fuzzers.*,1': 50,
                ',.*Generic.*,1': 100,
                ',.*Reconnaissance.*,1': 25,
                ',.*Shellcode.*,1': 15,
                ',.*Worms.*,1': 5},
         '10K': {',,0': 3340,
                 ',.*Analysis.*,1': 50,
                 ',.*Backdoor.*,1': 50,
                 ',.*DoS.*,1': 125,
                 ',.*Exploits.*,1': 200,
                 ',.*Fuzzers.*,1': 125,
                 ',.*Generic.*,1': 200,
                 ',.*Reconnaissance.*,1': 50,
                 ',.*Shellcode.*,1': 25,
                 ',.*Worms.*,1': 10}},
    'UNSW-NB15_3.csv' :
        {'5K': {',,0': 1580,
                ',.*Analysis.*,1': 25,
                ',.*Backdoor.*,1': 25,
                ',.*DoS.*,1': 50,
                ',.*Exploits.*,1': 100,
                ',.*Fuzzers.*,1': 50,
                ',.*Generic.*,1': 100,
                ',.*Reconnaissance.*,1': 25,
                ',.*Shellcode.*,1': 15,
                ',.*Worms.*,1': 5},
         '10K': {',,0': 3340,
                 ',.*Analysis.*,1': 50,
                 ',.*Backdoor.*,1': 50,
                 ',.*DoS.*,1': 125,
                 ',.*Exploits.*,1': 200,
                 ',.*Fuzzers.*,1': 125,
                 ',.*Generic.*,1': 200,
                 ',.*Reconnaissance.*,1': 50,
                 ',.*Shellcode.*,1': 25,
                 ',.*Worms.*,1': 10}},
    'UNSW-NB15_4.csv' :
        {'5K': {',,0': 1580,
                ',.*Analysis.*,1': 25,
                ',.*Backdoor.*,1': 25,
                ',.*DoS.*,1': 50,
                ',.*Exploits.*,1': 100,
                ',.*Fuzzers.*,1': 50,
                ',.*Generic.*,1': 100,
                ',.*Reconnaissance.*,1': 25,
                ',.*Shellcode.*,1': 15,
                ',.*Worms.*,1': 5},
         '10K': {',,0': 3340,
                 ',.*Analysis.*,1': 50,
                 ',.*Backdoor.*,1': 50,
                 ',.*DoS.*,1': 125,
                 ',.*Exploits.*,1': 200,
                 ',.*Fuzzers.*,1': 125,
                 ',.*Generic.*,1': 200,
                 ',.*Reconnaissance.*,1': 50,
                 ',.*Shellcode.*,1': 25,
                 ',.*Worms.*,1': 10}},
    }

##
# @name clean_output_files
#
# Objective: cleaning up all the file previously generated
#
# params: None
#
def clean_output_files():
    # to be done
    print("to be done")

##
# @name get_output_file
#
# Objective: 
#
# Parameters: None
#
# Returns:
#
def get_X_train_output_filename(output_filename_tag="notag"):
    X_train_output_filename = "X_train_" + output_filename_tag.strip() + ".csv"
    return X_train_output_filename

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
                      n_lines_to_cp=0):
    print('copying %d %s\'s lines into %s' % 
          (n_lines_to_cp, label_to_get, output_filename))

    line_cnt = 0
                # e.g. ,Benign$
    
    #reg_expr =  ','+label_to_get.replace(' ', r'\s')+'$'
    #reg_expr = reg_expr.replace(' ', r'\s')
    reg_expr = label_to_get.strip()+'$'
 
    with open(output_filename, 'a') as csv_output_file:
        with open(input_filename) as csv_input_file:
            for input_line in csv_input_file:
                if re.search(reg_expr, input_line):
                    csv_output_file.write(input_line)
                    line_cnt += 1
                    if line_cnt == n_lines_to_cp:
                        return line_cnt

    return line_cnt

##
# @name clean_output_files
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def generate_train_test_sets(output_file_tag="notag"):
    
    task_output_filename = get_X_train_output_filename(output_file_tag)
    
    # creating or truncating the output file
    open(task_output_filename, 'w')

    for global_processing_task in global_processing_dict.items():
        task_input_csv_filename = global_processing_task[0]
        
        if not output_file_tag in global_processing_task[1]:
            continue
            
        processing_task_dict = global_processing_task[1][output_file_tag]
        
        print('Processing:', task_input_csv_filename)
        for curr_task_tuple in processing_task_dict.items():
            label_to_get = curr_task_tuple[0]
            n_lines_to_cp = curr_task_tuple[1]
            n_sent_lines =  cp_lines_by_label(task_output_filename,
                                               task_input_csv_filename,
                                               label_to_get,
                                               n_lines_to_cp)
            
            if n_sent_lines == n_lines_to_cp:
                print('OK')
            else:
                print('ERROR')
                return RESULT_NOT_OK 

    return RESULT_OK
            
def _temportal_():
            labels_dict = curr_task_tuple[1]
            
            for curr_label_tuple in labels_dict.items():
                label_to_get = curr_label_tuple[0]
                n_lines_to_cp = curr_label_tuple[1]
                n_sent_lines =  cp_lines_by_label(task_output_filename,
                                                   task_input_csv_filename,
                                                   label_to_get,
                                                   n_lines_to_cp)
                
                if n_sent_lines == n_lines_to_cp:
                    print('OK')
                else:
                    print('ERROR')
                    return -1 
                    
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
    for output_file_tag in global_processing_tags:
        if RESULT_NOT_OK == generate_train_test_sets(output_file_tag):
            return RESULT_NOT_OK
                
if __name__ == "__main__":
    main()


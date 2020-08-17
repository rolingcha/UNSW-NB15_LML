# -*- coding: utf-8 -*-
"""
Created on Sun Aug  9 22:51:56 2020

@author: USER
"""

##
# @name get_unsw_nb15_output_filename
#
# Objective: 
#
# Parameters: None
#
# Returns:
#
def get_unsw_nb15_output_filename(output_filename_tag="notag"):
    return "UNSW_NB15_" + output_filename_tag.strip() + ".csv"

// Solution for IPK-packet-sniffer, 16.4.2022
// File:        args.h
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// File description


#pragma once

#include "ipk-sniffer.h"



/**
 * Get throught arguments and store them to settings struct  
 */
void parse_args(int argc, char *argv[], settings *sett);

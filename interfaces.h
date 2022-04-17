// Solution for IPK-packet-sniffer, 16.4.2022
// File:        interfaces.h
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// head file for interfaces.c 


#pragma once

#include <pcap.h>
#include "ipk-sniffer.h"

/**
 * Print all interfaces in system
 * exit with -3 if error 
 */
void print_interfaces();


/**
 * Check if interface exist 
 *  return true if yes 
 *  return false if not or error  
 */
bool interface_exist(char *int_name);
#pragma once

#include <cstdio>
#include <stdio.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"
#include <list>
#include <map>
#include <thread>

unsigned int mylinuxver();
unsigned int mylinux(int, int, int);
#include "header.h"

int execable(char *);
#define iface_is_link() (!_iface_has(ifd->real_iface, ":."))
#define iface_has(s) _iface_has(ifd->real_iface, (s))
#define iface_is_lo() ((!strcmp(ifd->logical_iface, LO_IFACE)) && (!no_loopback))
int _iface_has(char *, char *);
void cleanup_hwaddress(interface_defn * ifd, char **pparam, int argc, char **argv);
void make_hex_address(interface_defn * ifd, char **pparam, int argc, char **argv);
void compute_v4_addr(interface_defn * ifd, char **pparam, int argc, char **argv);
void compute_v4_mask(interface_defn * ifd, char **pparam, int argc, char **argv);
void compute_v4_broadcast(interface_defn * ifd, char **pparam, int argc, char **argv);
void set_preferred_lft(interface_defn * ifd, char **pparam, int argc, char **argv);
void get_token(interface_defn * ifd, char **pparam, int argc, char **argv);
void to_decimal(interface_defn * ifd, char **pparam, int argc, char **argv);
void map_value(interface_defn * ifd, char **pparam, int argc, char **argv);

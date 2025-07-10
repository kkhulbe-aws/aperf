#include "log.h"
#include "sys.h"
#include "config.h"
#include "hotline.h"
#include "fname_map.h"
#include "lat_map.h"
#include "bmiss_map.h"

int main(int argc, char *argv[]) {
    hotline(argc, argv);
    return 0;
}
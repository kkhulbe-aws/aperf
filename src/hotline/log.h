#pragma once

#include <stdio.h>
#include <stdlib.h>

// Preprocessor macro that is used for error handling throughout
// Exits on COND failure
#define ASSERT(COND, MSG)        \
  do {                           \
    if (!(COND)) {               \
      fprintf(stderr, MSG "\n"); \
      exit(EXIT_FAILURE);        \
    }                            \
  } while (0)

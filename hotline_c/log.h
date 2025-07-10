/**
 * @file log.h
 * @brief Logging and error handling macros
 * @author Kaustubh Khulbe
 * @ingroup Graviton Software
 */

#ifndef LOG_H_
#define LOG_H_

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
  } while (0);

#endif  // LOG_H_
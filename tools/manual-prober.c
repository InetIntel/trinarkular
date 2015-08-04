/*
 * This file is part of trinarkular
 *
 * Copyright (C) 2015 The Regents of the University of California.
 * Authors: Alistair King
 *
 * All rights reserved.
 *
 * This code has been developed by CAIDA at UC San Diego.
 * For more information, contact alistair@caida.org
 *
 * This source code is proprietary to the CAIDA group at UC San Diego and may
 * not be redistributed, published or disclosed without prior permission from
 * CAIDA.
 *
 * Report any bugs, questions or comments to alistair@caida.org
 *
 */
#include "config.h"

#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <timeseries.h>

#include "wandio_utils.h"
#include "utils.h"

#include "trinarkular.h"
#include "trinarkular_log.h"
#include "trinarkular_driver.h"

#define MAX_DRIVERS TRINARKULAR_PROBER_DRIVER_MAX_CNT

static trinarkular_probelist_t *pl = NULL;
static trinarkular_prober_t *prober = NULL;
static timeseries_t *timeseries = NULL;

/** Indicates that the prober is waiting to shutdown */
volatile sig_atomic_t prober_shutdown = 0;

/** The number of SIGINTs to catch before aborting */
#define HARD_SHUTDOWN 3

/** Handles SIGINT gracefully and shuts down */
static void catch_sigint(int sig)
{
  prober_shutdown++;
  if(prober_shutdown == HARD_SHUTDOWN)
    {
      fprintf(stderr, "caught %d SIGINT's. shutting down NOW\n",
	      HARD_SHUTDOWN);
      exit(-1);
    }

  fprintf(stderr, "caught SIGINT, shutting down at the next opportunity\n");

  if(prober != NULL)
    {
      trinarkular_prober_stop(prober);
    }

  signal(sig, catch_sigint);
}

static void timeseries_usage()
{
  assert(timeseries != NULL);
  timeseries_backend_t **backends = NULL;
  int i;

  backends = timeseries_get_all_backends(timeseries);

  fprintf(stderr,
	  "                        available backends:\n");
  for(i = 0; i < TIMESERIES_BACKEND_ID_LAST; i++)
    {
      /* skip unavailable backends */
      if(backends[i] == NULL)
	{
	  continue;
	}

      assert(timeseries_backend_get_name(backends[i]));
      fprintf(stderr, "                          - %s\n",
	      timeseries_backend_get_name(backends[i]));
    }
}

static void usage(char *name)
{
  const char **driver_names = trinarkular_driver_get_driver_names();
  int i;
  assert(driver_names != NULL);

  fprintf(stderr,
          "Usage: %s [options] -n prober-name probelist\n"
          "       -c <probecount>  periodic max number of probes to send per /24 (default: %d)\n"
          "       -d <duration>    periodic probing round duration in msec (default: %d)\n"
          "       -i <timeout>     periodic probing probe timeout in msec (default: %d)\n"
          "       -l <rounds>      periodic probing round limit (default: unlimited)\n"
          "       -n <prober-name> prober name (used in timeseries paths)\n"
          "       -p <driver>      probe driver to use (default: %s %s)\n"
          "                        options are:\n",
          name,
          TRINARKULAR_PROBER_PERIODIC_MAX_PROBECOUNT_DEFAULT,
          TRINARKULAR_PROBER_PERIODIC_ROUND_DURATION_DEFAULT,
          TRINARKULAR_PROBER_PERIODIC_PROBE_TIMEOUT_DEFAULT,
          TRINARKULAR_PROBER_DRIVER_DEFAULT,
          TRINARKULAR_PROBER_DRIVER_ARGS_DEFAULT);

  for (i=0; i <= TRINARKULAR_DRIVER_ID_MAX; i++) {
    if (driver_names[i] != NULL) {
      fprintf(stderr, "                          - %s\n", driver_names[i]);
    }
  }

  fprintf(stderr,
          "       -r <seed>        random number generator seed (default: NOW)\n"
          "       -s <slices>      periodic probing round slices (default: %d)\n"
          "       -t <ts-backend>  Timeseries backend to use, -t can be used multiple times\n",
          TRINARKULAR_PROBER_PERIODIC_ROUND_SLICES_DEFAULT);
  timeseries_usage();
}

static void cleanup()
{
  trinarkular_probelist_destroy(pl);
  pl = NULL;

  trinarkular_prober_destroy(prober);
  prober = NULL;

  timeseries_free(&timeseries);
}

int main(int argc, char **argv)
{
  int opt, prevoptind;

  char *probelist_file;

  char *driver_names[MAX_DRIVERS];
  int driver_names_cnt = 0;
  char *driver_arg_ptr = NULL;
  int i;

  int probecount;
  int probecount_set = 0;

  uint64_t duration;
  int duration_set = 0;

  uint32_t wait;
  int wait_set = 0;

  int round_limit;
  int round_limit_set = 0;

  char *prober_name = NULL;

  int slices;
  int slices_set = 0;

  int random_seed;
  int random_seed_set = 0;

  char *backends[TIMESERIES_BACKEND_ID_LAST];
  int backends_cnt = 0;
  char *backend_arg_ptr = NULL;
  timeseries_backend_t *backend = NULL;

  signal(SIGINT, catch_sigint);

  if ((timeseries = timeseries_init()) == NULL) {
    fprintf(stderr, "ERROR: Could not initialize libtimeseries\n");
    return -1;
  }

  while(prevoptind = optind,
	(opt = getopt(argc, argv, ":c:d:i:l:n:p:r:s:t:v?")) >= 0)
    {
      if (optind == prevoptind + 2 &&
          optarg && *optarg == '-' && *(optarg+1) != '\0') {
        opt = ':';
        -- optind;
      }
      switch(opt)
	{
        case 'c':
          probecount = strtoul(optarg, NULL, 10);
          if (probecount > UINT8_MAX) {
            fprintf(stderr, "ERROR: max probe count muse be < 256\n");
            usage(argv[0]);
            return -1;
          }
          probecount_set = 1;
          break;

	case 'd':
          duration = strtoull(optarg, NULL, 10);
          duration_set = 1;
          break;

        case 'i':
          wait = strtoul(optarg, NULL, 10);
          wait_set = 1;
          break;

        case 'l':
          round_limit = strtol(optarg, NULL, 10);
          round_limit_set = 1;
          break;

        case 'n':
          prober_name = strdup(optarg);
          assert(prober_name != NULL);
          break;

        case 'p':
          if (driver_names_cnt == MAX_DRIVERS) {
            fprintf(stderr, "ERROR: At most %d drivers can be specifed\n",
                    MAX_DRIVERS);
            goto err;
            return -1;
          }
          driver_names[driver_names_cnt] = strdup(optarg);
          assert(driver_names[driver_names_cnt] != NULL);
          driver_names_cnt++;
          break;

        case 'r':
          random_seed = strtol(optarg, NULL, 10);
          random_seed_set = 1;
          break;

        case 's':
          slices = strtol(optarg, NULL, 10);
          slices_set = 1;
          break;

        case 't':
	  backends[backends_cnt++] = strdup(optarg);
	  break;

	case ':':
	  fprintf(stderr, "ERROR: Missing option argument for -%c\n", optopt);
	  usage(argv[0]);
          goto err;
	  break;

	case '?':
	case 'v':
	  fprintf(stderr, "trinarkular version %d.%d.%d\n",
		  TRINARKULAR_MAJOR_VERSION,
		  TRINARKULAR_MID_VERSION,
		  TRINARKULAR_MINOR_VERSION);
	  usage(argv[0]);
	  goto err;
	  break;

	default:
	  usage(argv[0]);
	  goto err;
	}
    }

  if (optind >= argc) {
    fprintf(stderr, "ERROR: Probelist file must be specifed\n");
    usage(argv[0]);
    goto err;
  }
  probelist_file = argv[optind];

  if (prober_name == NULL) {
    fprintf(stderr, "ERROR: Prober name must be specified using -n\n");
    usage(argv[0]);
    goto err;
  }

  /* reset getopt for drivers to use */
  optind = 1;

  if(backends_cnt == 0) {
    fprintf(stderr,
            "ERROR: At least one timeseries backend must be specified using -t\n");
    usage(argv[0]);
    goto err;
  }

   /* enable the backends that were requested */
  for (i=0; i<backends_cnt; i++) {
    /* the string at backends[i] will contain the name of the plugin,
       optionally followed by a space and then the arguments to pass
       to the plugin */
    if ((backend_arg_ptr = strchr(backends[i], ' ')) != NULL) {
      /* set the space to a nul, which allows backends[i] to be used
         for the backend name, and then increment plugin_arg_ptr to
         point to the next character, which will be the start of the
         arg string (or at worst case, the terminating \0 */
      *backend_arg_ptr = '\0';
      backend_arg_ptr++;
    }

    /* lookup the backend using the name given */
    if ((backend = timeseries_get_backend_by_name(timeseries,
                                                  backends[i])) == NULL) {
      fprintf(stderr, "ERROR: Invalid backend name (%s)\n",
              backends[i]);
      usage(argv[0]);
      goto err;
    }

    if (timeseries_enable_backend(backend, backend_arg_ptr) != 0) {
      fprintf(stderr, "ERROR: Failed to initialized backend (%s)",
              backends[i]);
      usage(argv[0]);
      goto err;
    }

    /* free the string we dup'd */
    free(backends[i]);
    backends[i] = NULL;
  }

  if ((prober = trinarkular_prober_create(prober_name, timeseries)) == NULL) {
    goto err;
  }

  if (probecount_set != 0) {
    trinarkular_prober_set_periodic_max_probecount(prober, probecount);
  }

  if (duration_set != 0) {
    trinarkular_prober_set_periodic_round_duration(prober, duration);
  }

  if (wait_set != 0) {
    trinarkular_prober_set_periodic_probe_timeout(prober, wait);
  }

  if (round_limit_set != 0) {
    trinarkular_prober_set_periodic_round_limit(prober, round_limit);
  }

  if (slices_set != 0) {
    trinarkular_prober_set_periodic_round_slices(prober, slices);
  }

  if (random_seed_set != 0) {
    trinarkular_prober_set_random_seed(prober, random_seed);
  }

  for (i=0; i<driver_names_cnt; i++) {
    if (driver_names[i] != NULL) {
      /* the driver_name string will contain the name of the driver, optionally
         followed by a space and then the arguments to pass to the driver */
      if ((driver_arg_ptr = strchr(driver_names[i], ' ')) != NULL) {
        /* set the space to a nul, which allows driver_name to be used for the
           provider name, and then increment driver_arg_ptr to point to the next
           character, which will be the start of the arg string (or at worst case,
           the terminating \0 */
        *driver_arg_ptr = '\0';
        driver_arg_ptr++;
      }

      if (trinarkular_prober_add_driver(prober,
                                        driver_names[i], driver_arg_ptr) != 0) {
        goto err;
      }
    }
  }

  if ((pl = trinarkular_probelist_create_from_file(probelist_file)) == NULL) {
    goto err;
  }

  trinarkular_prober_assign_probelist(prober, pl);
  // prober now owns pl
  pl = NULL;

  // this will block indefinitely
  if (trinarkular_prober_start(prober) != 0) {
    goto err;
  }

  cleanup();
  return 0;

 err:
  cleanup();
  return -1;
}

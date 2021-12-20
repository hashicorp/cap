#!/bin/bash

# this is just part of an example way to use your own directory with the cli.
#
# see: https://github.com/rroemhild/docker-test-openldap 
# for more information about this docker file which is running an openldap
# service.  The server is initialized with the example domain planetexpress.com
# with data from the Futurama Wiki. 
docker run --rm -p 10389:10389 -p 10636:10636 rroemhild/test-openldap
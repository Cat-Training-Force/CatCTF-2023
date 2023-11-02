#!/bin/sh

echo "catctf{this_is_test_flag_for_ez_code}" > /flag

# echo $GZCTF_FLAG > /flag

chmod 755 /flag

unset GZCTF_FLAG

rm -f /flag.sh

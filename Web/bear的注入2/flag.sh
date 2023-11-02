#!/bin/sh
echo "catctf{this_is_test_flag_for_sql_union_injection}" > /flag

# echo $GZCTF_FLAG > /flag

chmod 755 /flag

unset GZCTF_FLAG

mysql -e "source /tmp/catctf.sql;" -uroot -proot



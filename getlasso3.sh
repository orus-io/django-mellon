#!/bin/sh

# Get venv site-packages path
DSTDIR=`python3 -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())'`

# Get not venv site-packages path
# Remove first path (assuming that is the venv path)
NONPATH=`echo $PATH | sed 's/^[^:]*://'`
SRCDIR=`PATH=$NONPATH python3 -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())'`

# Clean up
rm -f $DSTDIR/lasso.*
rm -f $DSTDIR/_lasso.*

# Link
ln -sv /usr/lib/python3/dist-packages/lasso.py $DSTDIR/
ln -sv /usr/lib/python3/dist-packages/_lasso.cpython-36m-x86_64-linux-gnu.so $DSTDIR/

exit 0
